#include "scadaguard/scheduler.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace scadaguard {
namespace {

using SteadyClock = std::chrono::steady_clock;

struct Execution {
    std::promise<CheckResult> promise;
    std::shared_future<CheckResult> future{promise.get_future().share()};
    std::stop_source stop_source;
    SteadyClock::time_point submitted_at{SteadyClock::now()};
    SteadyClock::time_point deadline;
    std::atomic_bool timed_out{false};
};

struct CheckSlot {
    explicit CheckSlot(std::shared_ptr<IHealthCheck> value) : check(std::move(value)) {}

    std::shared_ptr<IHealthCheck> check;
    std::mutex mutex;
    std::shared_ptr<Execution> execution;
    bool scheduled{false};
};

struct WorkItem {
    std::shared_ptr<CheckSlot> slot;
    std::shared_ptr<Execution> execution;
};

CheckResult internal_error(const IHealthCheck& check, const std::string& message) {
    return {
        check.id(), "internal",   HealthStatus::Unknown,
        message,    Clock::now(), {{"problem_type", "internal_error"}},
    };
}

} // namespace

struct CheckScheduler::Core {
    explicit Core(const std::size_t count) : worker_count(count) {}

    const std::size_t worker_count;
    mutable std::mutex mutex;
    std::condition_variable condition;
    std::deque<WorkItem> queue;
    std::vector<std::shared_ptr<CheckSlot>> slots;
    bool stopping{false};
};

namespace {

void finish_execution(const WorkItem& work, CheckResult result) noexcept {
    try {
        work.execution->promise.set_value(std::move(result));
    } catch (...) {
        // A promise can only be completed once. The worker must never terminate the process.
    }

    std::scoped_lock slot_lock(work.slot->mutex);
    if (work.slot->execution == work.execution) {
        work.slot->scheduled = false;
    }
}

template <typename CorePointer> void worker_loop(const CorePointer& core) {
    for (;;) {
        WorkItem work;
        {
            std::unique_lock lock(core->mutex);
            core->condition.wait(lock, [&] { return core->stopping || !core->queue.empty(); });
            if (core->stopping && core->queue.empty()) {
                return;
            }
            work = std::move(core->queue.front());
            core->queue.pop_front();
        }

        if (work.execution->timed_out.load() || work.execution->stop_source.stop_requested()) {
            finish_execution(
                work, internal_error(*work.slot->check, "Check was cancelled before execution"));
            continue;
        }

        const auto started_at = SteadyClock::now();
        CheckResult result;
        try {
            result = work.slot->check->execute(work.execution->stop_source.get_token());
        } catch (const std::exception& error) {
            result =
                internal_error(*work.slot->check, "Check failed: " + std::string(error.what()));
        } catch (...) {
            result = internal_error(*work.slot->check, "Check failed with an unknown exception");
        }

        result.details["duration_ms"] =
            std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - started_at)
                .count();
        finish_execution(work, std::move(result));
    }
}

} // namespace

CheckScheduler::CheckScheduler(const std::size_t worker_count)
    : core_(std::make_shared<Core>(worker_count)) {
    if (worker_count == 0) {
        throw std::invalid_argument("scheduler worker count must be greater than zero");
    }

    // Workers are intentionally detached. They only retain the shared Core and check slots.
    // A non-cooperative check can therefore occupy one bounded slot without blocking service
    // shutdown or causing an unbounded number of replacement threads.
    for (std::size_t index = 0; index < worker_count; ++index) {
        std::thread([core = core_] { worker_loop(core); }).detach();
    }
}

CheckScheduler::~CheckScheduler() {
    std::vector<std::shared_ptr<CheckSlot>> slots;
    {
        std::scoped_lock lock(core_->mutex);
        core_->stopping = true;
        slots = core_->slots;
    }
    for (const auto& slot : slots) {
        std::scoped_lock slot_lock(slot->mutex);
        if (slot->execution) {
            slot->execution->stop_source.request_stop();
        }
    }
    core_->condition.notify_all();
}

void CheckScheduler::add(std::shared_ptr<IHealthCheck> check) {
    if (!check) {
        throw std::invalid_argument("check must not be null");
    }

    std::scoped_lock lock(core_->mutex);
    const auto duplicate = std::ranges::any_of(
        core_->slots, [&](const auto& slot) { return slot->check->id() == check->id(); });
    if (duplicate) {
        throw std::invalid_argument("duplicate check id: " + check->id());
    }
    core_->slots.push_back(std::make_shared<CheckSlot>(std::move(check)));
}

std::vector<CheckResult> CheckScheduler::run_once(const std::chrono::milliseconds timeout,
                                                  const std::stop_token stop_token) {
    if (timeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("check timeout must be greater than zero");
    }

    std::vector<std::shared_ptr<CheckSlot>> slots;
    {
        std::scoped_lock lock(core_->mutex);
        slots = core_->slots;
    }

    struct Awaited {
        std::shared_ptr<CheckSlot> slot;
        std::shared_ptr<Execution> execution;
    };
    std::vector<Awaited> awaited;
    awaited.reserve(slots.size());

    for (const auto& slot : slots) {
        std::shared_ptr<Execution> execution;
        bool enqueue = false;
        {
            std::scoped_lock slot_lock(slot->mutex);
            if (!slot->scheduled) {
                execution = std::make_shared<Execution>();
                execution->deadline = execution->submitted_at + timeout;
                slot->execution = execution;
                slot->scheduled = true;
                enqueue = true;
            } else {
                execution = slot->execution;
            }
        }

        awaited.push_back({slot, execution});
        if (enqueue) {
            {
                std::scoped_lock lock(core_->mutex);
                if (!core_->stopping) {
                    core_->queue.push_back({slot, execution});
                }
            }
            core_->condition.notify_one();
        }
    }

    std::vector<CheckResult> results;
    results.reserve(awaited.size());
    for (const auto& item : awaited) {
        while (!stop_token.stop_requested() && SteadyClock::now() < item.execution->deadline &&
               item.execution->future.wait_for(std::chrono::milliseconds(10)) !=
                   std::future_status::ready) {
        }

        if (item.execution->future.wait_for(std::chrono::milliseconds::zero()) ==
            std::future_status::ready) {
            results.push_back(item.execution->future.get());
            continue;
        }

        item.execution->timed_out.store(true);
        item.execution->stop_source.request_stop();
        const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  SteadyClock::now() - item.execution->submitted_at)
                                  .count();
        results.push_back({
            item.slot->check->id(),
            "internal",
            HealthStatus::Unknown,
            stop_token.stop_requested() ? "Check cancelled during scheduler stop"
                                        : "Check timed out",
            Clock::now(),
            {{"problem_type", stop_token.stop_requested() ? "cancelled" : "timeout"},
             {"duration_ms", duration}},
        });
    }
    return results;
}

void CheckScheduler::run(const std::chrono::milliseconds interval,
                         const std::chrono::milliseconds timeout, Callback callback,
                         const std::stop_token stop_token) {
    std::mutex wait_mutex;
    std::condition_variable_any wait_condition;
    while (!stop_token.stop_requested()) {
        callback(run_once(timeout, stop_token));
        std::unique_lock lock(wait_mutex);
        wait_condition.wait_for(lock, stop_token, interval, [] { return false; });
    }
}

std::size_t CheckScheduler::size() const noexcept {
    std::scoped_lock lock(core_->mutex);
    return core_->slots.size();
}

std::size_t CheckScheduler::worker_count() const noexcept {
    return core_->worker_count;
}

} // namespace scadaguard
