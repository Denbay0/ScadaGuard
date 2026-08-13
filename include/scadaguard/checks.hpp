#pragma once

#include "scadaguard/config.hpp"
#include "scadaguard/model.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>

namespace scadaguard {

struct LogCheckState {
    std::string check_id;
    std::uint64_t offset{};
    std::uint64_t file_id{};
    std::uint32_t volume_serial{};
    TimePoint updated_at{};
};

struct FileCheckState {
    std::string check_id;
    std::uint64_t size{};
    TimePoint modified_at{};
    TimePoint last_change_at{};
};

class ICheckStateStore {
  public:
    virtual ~ICheckStateStore() = default;
    virtual std::optional<LogCheckState> load_log_state(const std::string& check_id) const = 0;
    virtual void save_log_state(const LogCheckState& state) = 0;
    virtual std::optional<FileCheckState> load_file_state(const std::string& check_id) const = 0;
    virtual void save_file_state(const FileCheckState& state) = 0;
};

class IHealthCheck {
  public:
    virtual ~IHealthCheck() = default;
    virtual std::string id() const = 0;
    virtual CheckResult execute(std::stop_token stop_token) = 0;
};

class ProcessCheck final : public IHealthCheck {
  public:
    explicit ProcessCheck(ProcessCheckConfig config);
    std::string id() const override;
    CheckResult execute(std::stop_token) override;

  private:
    ProcessCheckConfig config_;
};
class WindowsServiceCheck final : public IHealthCheck {
  public:
    explicit WindowsServiceCheck(ServiceCheckConfig config);
    std::string id() const override;
    CheckResult execute(std::stop_token) override;

  private:
    ServiceCheckConfig config_;
};
class TcpPortCheck final : public IHealthCheck {
  public:
    explicit TcpPortCheck(TcpCheckConfig config);
    std::string id() const override;
    CheckResult execute(std::stop_token) override;

  private:
    TcpCheckConfig config_;
};
class DiskSpaceCheck final : public IHealthCheck {
  public:
    explicit DiskSpaceCheck(DiskCheckConfig config);
    std::string id() const override;
    CheckResult execute(std::stop_token) override;

  private:
    DiskCheckConfig config_;
};
class FileActivityCheck final : public IHealthCheck {
  public:
    explicit FileActivityCheck(FileActivityCheckConfig config,
                               ICheckStateStore* state_store = nullptr);
    std::string id() const override;
    CheckResult execute(std::stop_token) override;

  private:
    FileActivityCheckConfig config_;
    std::uintmax_t previous_size_{};
    TimePoint last_change_{};
    bool initialized_{};
    ICheckStateStore* state_store_{};
};
class LogPatternCheck final : public IHealthCheck {
  public:
    explicit LogPatternCheck(LogCheckConfig config, ICheckStateStore* state_store = nullptr);
    std::string id() const override;
    CheckResult execute(std::stop_token) override;

  private:
    LogCheckConfig config_;
    std::uintmax_t offset_{};
    std::uint64_t file_id_{};
    std::uint32_t volume_serial_{};
    bool identity_initialized_{};
    ICheckStateStore* state_store_{};
};

} // namespace scadaguard
