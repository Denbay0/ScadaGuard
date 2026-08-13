#pragma once

#include <filesystem>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace scadaguard {

struct DesiredAgentConfiguration {
    std::uint64_t version{};
    std::string hash;
    std::optional<std::filesystem::path> confirmed_archive;
    nlohmann::json archive_mapping;
    std::vector<std::filesystem::path> confirmed_logs;
    std::vector<std::string> monitored_signals;
    nlohmann::json thresholds = nlohmann::json::object();
    int monitoring_interval_seconds{30};
    std::optional<std::string> server_url;
    std::optional<std::string> rescan_requested_at;
    nlohmann::json raw;
};

DesiredAgentConfiguration validate_desired_agent_configuration(const nlohmann::json& value);
std::string desired_configuration_hash(const nlohmann::json& configuration);

} // namespace scadaguard
