#pragma once

#include "scadaguard/config.hpp"
#include "scadaguard/model.hpp"

#include <memory>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace httplib {
class Server;
}

namespace scadaguard {

class AgentState {
  public:
    AgentState(AgentConfig agent, ConfigurationStatus configuration, std::string boot_id);

    void update(std::vector<CheckResult> checks, std::vector<Incident> incidents,
                std::vector<SignalSample> signals, std::size_t queue_size,
                std::optional<TimePoint> oldest_queued_at);

    nlohmann::json health() const;
    nlohmann::json checks() const;
    nlohmann::json incidents() const;
    nlohmann::json signals() const;
    nlohmann::json configuration_status() const;
    nlohmann::json queue_status() const;
    nlohmann::json version() const;
    nlohmann::json discovery() const;
    void update_discovery(nlohmann::json report);
    std::string metrics() const;

  private:
    mutable std::mutex mutex_;
    AgentConfig agent_;
    ConfigurationStatus configuration_;
    std::string boot_id_;
    std::string hostname_;
    std::string windows_version_;
    TimePoint started_;
    std::vector<CheckResult> checks_;
    std::vector<Incident> incidents_;
    std::vector<SignalSample> signals_;
    std::size_t queue_size_{};
    std::optional<TimePoint> oldest_queued_at_;
    nlohmann::json discovery_{{"masterscada", {{"detected", false}, {"status", "not_found"}}}};
};

class LocalHttpServer {
  public:
    LocalHttpServer(LocalApiConfig config, std::shared_ptr<AgentState> state,
                    std::function<nlohmann::json()> rescan = {});
    ~LocalHttpServer();
    void start();
    void stop();

  private:
    LocalApiConfig config_;
    std::shared_ptr<AgentState> state_;
    std::function<nlohmann::json()> rescan_;
    std::unique_ptr<httplib::Server> server_;
    std::jthread thread_;
};

} // namespace scadaguard
