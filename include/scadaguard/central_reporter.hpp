#pragma once

#include "scadaguard/config.hpp"
#include "scadaguard/local_storage.hpp"

#include <chrono>
#include <cstddef>
#include <stop_token>

namespace scadaguard {
class ICentralReporter {
  public:
    virtual ~ICentralReporter() = default;
    virtual bool send_heartbeat(const nlohmann::json&, std::stop_token) = 0;
    virtual bool send_check_results(const nlohmann::json&, std::stop_token) = 0;
    virtual bool send_incidents(const nlohmann::json&, std::stop_token) = 0;
    virtual bool send_signal_samples(const nlohmann::json&, std::stop_token) = 0;
};
class DisabledCentralReporter final : public ICentralReporter {
  public:
    bool send_heartbeat(const nlohmann::json&, std::stop_token) override {
        return true;
    }
    bool send_check_results(const nlohmann::json&, std::stop_token) override {
        return true;
    }
    bool send_incidents(const nlohmann::json&, std::stop_token) override {
        return true;
    }
    bool send_signal_samples(const nlohmann::json&, std::stop_token) override {
        return true;
    }
};
class HttpCentralReporter final : public ICentralReporter {
  public:
    HttpCentralReporter(CentralServerConfig config, LocalStorage& storage);
    bool send_heartbeat(const nlohmann::json&, std::stop_token) override;
    bool send_check_results(const nlohmann::json&, std::stop_token) override;
    bool send_incidents(const nlohmann::json&, std::stop_token) override;
    bool send_signal_samples(const nlohmann::json&, std::stop_token) override;
    std::size_t flush(std::stop_token);

  private:
    bool send(const char* path, const nlohmann::json&, std::stop_token);
    bool send_or_queue(const char* path, const nlohmann::json&, std::stop_token);
    CentralServerConfig config_;
    LocalStorage& storage_;
    unsigned retry_attempt_{};
    std::chrono::steady_clock::time_point next_retry_{};
};
} // namespace scadaguard
