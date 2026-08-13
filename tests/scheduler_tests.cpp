#include "scadaguard/scheduler.hpp"
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <thread>
using namespace scadaguard;
using namespace std::chrono_literals;
namespace {
class CooperativeCheck final : public IHealthCheck {
  public:
    std::string id() const override {
        return "cooperative";
    }
    CheckResult execute(std::stop_token stop) override {
        while (!stop.stop_requested())
            std::this_thread::sleep_for(1ms);
        return {"cooperative", "test", HealthStatus::Ok, "stopped", Clock::now(), {}};
    }
};
class ThrowingCheck final : public IHealthCheck {
  public:
    std::string id() const override {
        return "throw";
    }
    CheckResult execute(std::stop_token) override {
        throw std::runtime_error("boom");
    }
};
class FastCheck final : public IHealthCheck {
  public:
    explicit FastCheck(std::string check_id = "fast") : check_id_(std::move(check_id)) {}

    std::string id() const override {
        return check_id_;
    }

    CheckResult execute(std::stop_token) override {
        return {check_id_, "test", HealthStatus::Ok, "completed", Clock::now(), {}};
    }

  private:
    std::string check_id_;
};
class SlowCountingCheck final : public IHealthCheck {
  public:
    std::string id() const override {
        return "slow-counting";
    }

    CheckResult execute(std::stop_token) override {
        ++executions;
        std::this_thread::sleep_for(100ms);
        return {id(), "test", HealthStatus::Ok, "completed", Clock::now(), {}};
    }

    std::atomic_int executions{0};
};
} // namespace
TEST_CASE("scheduler completes a normal check and records duration") {
    CheckScheduler scheduler(2);
    scheduler.add(std::make_shared<FastCheck>());

    const auto results = scheduler.run_once(1s);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().status == HealthStatus::Ok);
    REQUIRE(results.front().details.contains("duration_ms"));
    REQUIRE(scheduler.worker_count() == 2);
}
TEST_CASE("scheduler times out and stops a cooperative check") {
    CheckScheduler scheduler;
    scheduler.add(std::make_shared<CooperativeCheck>());
    const auto started = std::chrono::steady_clock::now();
    auto results = scheduler.run_once(10ms);
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].status == HealthStatus::Unknown);
    REQUIRE(std::chrono::steady_clock::now() - started < 1s);
}
TEST_CASE("scheduler does not start the same timed out check twice") {
    CheckScheduler scheduler(2);
    auto check = std::make_shared<SlowCountingCheck>();
    scheduler.add(check);

    const auto first = scheduler.run_once(10ms);
    const auto second = scheduler.run_once(10ms);

    REQUIRE(first.front().status == HealthStatus::Unknown);
    REQUIRE(second.front().status == HealthStatus::Unknown);
    REQUIRE(check->executions.load() == 1);
}
TEST_CASE("a slow check does not prevent another worker from completing") {
    CheckScheduler scheduler(2);
    scheduler.add(std::make_shared<SlowCountingCheck>());
    scheduler.add(std::make_shared<FastCheck>());

    const auto results = scheduler.run_once(20ms);

    REQUIRE(results.size() == 2);
    REQUIRE(results[0].status == HealthStatus::Unknown);
    REQUIRE(results[1].status == HealthStatus::Ok);
}
TEST_CASE("scheduler rejects duplicate check identifiers") {
    CheckScheduler scheduler;
    scheduler.add(std::make_shared<FastCheck>("duplicate"));
    REQUIRE_THROWS_AS(scheduler.add(std::make_shared<FastCheck>("duplicate")),
                      std::invalid_argument);
}
TEST_CASE("scheduler isolates check exceptions") {
    CheckScheduler scheduler;
    scheduler.add(std::make_shared<ThrowingCheck>());
    auto result = scheduler.run_once(1s);
    REQUIRE(result[0].status == HealthStatus::Unknown);
    REQUIRE(result[0].message.find("boom") != std::string::npos);
}
TEST_CASE("scheduler loop stops through stop token") {
    CheckScheduler scheduler;
    std::stop_source stop;
    std::jthread thread([&] { scheduler.run(1s, 1s, [](const auto&) {}, stop.get_token()); });
    stop.request_stop();
    thread.join();
    SUCCEED();
}
