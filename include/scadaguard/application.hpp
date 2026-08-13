#pragma once

#include "scadaguard/config.hpp"
#include <memory>
#include <stop_token>

namespace scadaguard {
class Application {
  public:
    explicit Application(AppConfig config);
    ~Application();
    nlohmann::json run_once(std::stop_token stop = {});
    void run(std::stop_token stop);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace scadaguard
