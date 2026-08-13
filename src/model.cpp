#include "scadaguard/model.hpp"

#include <format>
#include <array>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

namespace scadaguard {

std::string to_string(const HealthStatus status) {
    switch (status) {
    case HealthStatus::Unknown:
        return "unknown";
    case HealthStatus::Ok:
        return "ok";
    case HealthStatus::Warning:
        return "warning";
    case HealthStatus::Critical:
        return "critical";
    }
    throw std::invalid_argument("invalid health status");
}

HealthStatus health_status_from_string(const std::string& value) {
    if (value == "unknown")
        return HealthStatus::Unknown;
    if (value == "ok")
        return HealthStatus::Ok;
    if (value == "warning")
        return HealthStatus::Warning;
    if (value == "critical")
        return HealthStatus::Critical;
    throw std::invalid_argument("invalid health status: " + value);
}

std::string format_utc(const TimePoint value) {
    return std::format("{:%FT%TZ}", std::chrono::floor<std::chrono::seconds>(value));
}

TimePoint parse_utc(const std::string& value) {
    std::chrono::sys_seconds result;
    std::istringstream input(value);
    input >> std::chrono::parse("%FT%TZ", result);
    if (input.fail())
        throw std::invalid_argument("invalid UTC ISO 8601 timestamp: " + value);
    return result;
}

std::string generate_uuid_v4() {
    std::array<unsigned char, 16> bytes{};
    std::random_device random;
    for (auto& byte : bytes) {
        byte = static_cast<unsigned char>(random());
    }
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index == 4 || index == 6 || index == 8 || index == 10) {
            output << '-';
        }
        output << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    }
    return output.str();
}

void to_json(nlohmann::json& json, const HealthStatus& value) {
    json = to_string(value);
}
void from_json(const nlohmann::json& json, HealthStatus& value) {
    value = health_status_from_string(json.get<std::string>());
}

void to_json(nlohmann::json& j, const CheckResult& v) {
    j = {{"check_id", v.check_id},
         {"component", v.component},
         {"status", v.status},
         {"message", v.message},
         {"observed_at", format_utc(v.observed_at)},
         {"details", v.details}};
}
void from_json(const nlohmann::json& j, CheckResult& v) {
    j.at("check_id").get_to(v.check_id);
    j.at("component").get_to(v.component);
    j.at("status").get_to(v.status);
    j.at("message").get_to(v.message);
    v.observed_at = parse_utc(j.at("observed_at").get<std::string>());
    v.details = j.value("details", nlohmann::json::object());
}
void to_json(nlohmann::json& j, const SignalSample& v) {
    j = {{"signal_id", v.signal_id},
         {"value", v.value},
         {"source_timestamp", format_utc(v.source_timestamp)},
         {"received_timestamp", format_utc(v.received_timestamp)},
         {"quality", v.quality}};
}
void from_json(const nlohmann::json& j, SignalSample& v) {
    j.at("signal_id").get_to(v.signal_id);
    j.at("value").get_to(v.value);
    v.source_timestamp = parse_utc(j.at("source_timestamp").get<std::string>());
    v.received_timestamp = parse_utc(j.at("received_timestamp").get<std::string>());
    j.at("quality").get_to(v.quality);
}
void to_json(nlohmann::json& j, const Incident& v) {
    j = {{"incident_id", v.incident_id},
         {"incident_key", v.incident_key},
         {"component", v.component},
         {"severity", v.severity},
         {"title", v.title},
         {"description", v.description},
         {"opened_at", format_utc(v.opened_at)},
         {"closed_at",
          v.closed_at ? nlohmann::json(format_utc(*v.closed_at)) : nlohmann::json(nullptr)},
         {"active", v.active},
         {"details", v.details},
         {"source", v.source},
         {"last_seen_at", format_utc(v.last_seen_at == TimePoint{} ? v.opened_at : v.last_seen_at)},
         {"occurrence_count", v.occurrence_count}};
}
void from_json(const nlohmann::json& j, Incident& v) {
    j.at("incident_id").get_to(v.incident_id);
    j.at("incident_key").get_to(v.incident_key);
    j.at("component").get_to(v.component);
    j.at("severity").get_to(v.severity);
    j.at("title").get_to(v.title);
    j.at("description").get_to(v.description);
    v.opened_at = parse_utc(j.at("opened_at").get<std::string>());
    v.closed_at = j.at("closed_at").is_null()
                      ? std::nullopt
                      : std::optional{parse_utc(j.at("closed_at").get<std::string>())};
    j.at("active").get_to(v.active);
    v.details = j.value("details", nlohmann::json::object());
    v.source = j.value("source", std::string("agent"));
    v.last_seen_at = j.contains("last_seen_at") ? parse_utc(j.at("last_seen_at").get<std::string>())
                                                : v.opened_at;
    v.occurrence_count = j.value("occurrence_count", std::uint64_t{1});
}

} // namespace scadaguard
