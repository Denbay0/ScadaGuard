#pragma once

#include "scadaguard/model.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace scadaguard {

struct AgentConfig {
    std::string agent_id;
    std::string site_id;
    std::string host_id;
    int poll_interval_seconds{30};
    int check_timeout_seconds{10};
    std::size_t scheduler_worker_count{4};
    std::string runtime_mode{"unknown"};
};
struct LoggingConfig {
    std::filesystem::path directory;
    std::string level{"info"};
    std::string format{"text"};
    std::size_t max_file_size_mb{20};
    std::size_t max_files{10};
};
struct LocalApiConfig {
    bool enabled{true};
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{9180};
};
struct CentralServerConfig {
    bool enabled{};
    bool production{true};
    std::string base_url;
    int heartbeat_interval_seconds{30};
    int request_timeout_seconds{10};
    std::size_t max_queue_size{10000};
};
struct ProcessCheckConfig {
    std::string id;
    std::string process_name;
    bool required{true};
};
struct ServiceCheckConfig {
    std::string id;
    std::string service_name;
    bool required{true};
};
struct TcpCheckConfig {
    std::string id;
    std::string host;
    std::uint16_t port{};
    int timeout_ms{3000};
};
struct DiskCheckConfig {
    std::string id;
    std::filesystem::path path;
    double warning_free_percent{15};
    double critical_free_percent{7};
    double critical_free_gb{5};
};
struct FileActivityCheckConfig {
    std::string id;
    std::filesystem::path path;
    int warning_unchanged_seconds{300};
    int critical_unchanged_seconds{900};
    bool fail_on_shrink{true};
};
struct LogPatternGroup {
    std::string name;
    HealthStatus severity{HealthStatus::Warning};
    std::vector<std::string> patterns;
};
struct LogCheckConfig {
    std::string id;
    std::filesystem::path path;
    bool case_sensitive{};
    std::size_t max_read_bytes{1048576};
    std::vector<LogPatternGroup> groups;
};

struct SignalRule {
    std::string signal_id;
    bool enabled{true};
    std::optional<double> minimum;
    std::optional<double> maximum;
    std::vector<std::string> allowed_quality{"Good"};
    std::vector<double> invalid_sentinels;
    int max_age_seconds{60};
    std::optional<int> frozen_after_seconds;
    double frozen_epsilon{0.01};
    std::optional<double> max_rate_per_second;
    std::optional<int> expected_period_seconds;
    double missing_period_multiplier{3};
    int archive_delay_seconds{30};
    int archive_match_window_seconds{10};
    double archive_absolute_tolerance{0.1};
    double archive_relative_tolerance{0.001};
};

struct DataSourceConfig {
    std::string type{"mock"};
    nlohmann::json options = nlohmann::json::object();
};
struct ConfigurationStatus {
    bool loaded{false};
    std::string path;
    std::string hash;
    std::vector<std::string> warnings;
    std::vector<std::string> enabled_data_sources;
    std::vector<std::string> unconfigured_subsystems;
    TimePoint loaded_at{};
};
struct AppConfig {
    AgentConfig agent;
    LoggingConfig logging;
    LocalApiConfig local_api;
    CentralServerConfig central_server;
    std::filesystem::path state_database;
    std::vector<ProcessCheckConfig> process_checks;
    std::vector<ServiceCheckConfig> service_checks;
    std::vector<TcpCheckConfig> tcp_checks;
    std::vector<DiskCheckConfig> disk_checks;
    std::vector<FileActivityCheckConfig> file_activity_checks;
    std::vector<LogCheckConfig> log_checks;
    DataSourceConfig current_data_source;
    DataSourceConfig archive_data_source;
    std::vector<SignalRule> signals;
    ConfigurationStatus status;
};

class ConfigurationError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

AppConfig load_config(const std::filesystem::path& path);
AppConfig parse_config(const nlohmann::json& json);
std::vector<std::string> validate_config(const AppConfig& config);
std::filesystem::path default_config_path();
std::filesystem::path default_state_database_path();
std::string configuration_hash(const nlohmann::json& json);

} // namespace scadaguard
