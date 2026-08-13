#pragma once

#include "scadaguard/checks.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <stop_token>
#include <vector>

namespace scadaguard {

class CheckScheduler {
  public:
    using Callback = std::function<void(const std::vector<CheckResult>&)>;

    explicit CheckScheduler(std::size_t worker_count = 4);
    ~CheckScheduler();

    CheckScheduler(const CheckScheduler&) = delete;
    CheckScheduler& operator=(const CheckScheduler&) = delete;

    void add(std::shared_ptr<IHealthCheck> check);
    std::vector<CheckResult> run_once(std::chrono::milliseconds timeout,
                                      std::stop_token stop_token = {});
    void run(std::chrono::milliseconds interval, std::chrono::milliseconds timeout,
             Callback callback, std::stop_token stop_token);
    std::size_t size() const noexcept;
    std::size_t worker_count() const noexcept;

  private:
    struct Core;
    std::shared_ptr<Core> core_;
};

} // namespace scadaguard
