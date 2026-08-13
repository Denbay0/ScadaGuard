#pragma once

#include <chrono>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace scadaguard {

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

enum class HealthStatus { Unknown, Ok, Warning, Critical };

struct CheckResult {
    std::string check_id;
    std::string component;
    HealthStatus status{HealthStatus::Unknown};
    std::string message;
    TimePoint observed_at{};
    nlohmann::json details = nlohmann::json::object();
};

struct SignalSample {
    std::string signal_id;
    double value{};
    TimePoint source_timestamp{};
    TimePoint received_timestamp{};
    std::string quality;
};

struct Incident {
    std::string incident_id;
    std::string incident_key;
    std::string component;
    HealthStatus severity{HealthStatus::Unknown};
    std::string title;
    std::string description;
    TimePoint opened_at{};
    std::optional<TimePoint> closed_at;
    bool active{};
    nlohmann::json details = nlohmann::json::object();
    std::string source{"agent"};
    TimePoint last_seen_at{};
    std::uint64_t occurrence_count{1};
};

std::string to_string(HealthStatus status);
HealthStatus health_status_from_string(const std::string& value);
std::string format_utc(TimePoint value);
TimePoint parse_utc(const std::string& value);
std::string generate_uuid_v4();

void to_json(nlohmann::json& json, const HealthStatus& value);
void from_json(const nlohmann::json& json, HealthStatus& value);
void to_json(nlohmann::json& json, const CheckResult& value);
void from_json(const nlohmann::json& json, CheckResult& value);
void to_json(nlohmann::json& json, const SignalSample& value);
void from_json(const nlohmann::json& json, SignalSample& value);
void to_json(nlohmann::json& json, const Incident& value);
void from_json(const nlohmann::json& json, Incident& value);

} // namespace scadaguard
