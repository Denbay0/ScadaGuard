#include "scadaguard/config.hpp"

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>

namespace scadaguard {
namespace {

template <typename T>
T required(const nlohmann::json& j, const char* key, const std::string& path) {
    if (!j.contains(key))
        throw ConfigurationError(path + "." + key + " is required");
    try {
        return j.at(key).get<T>();
    } catch (const nlohmann::json::exception& e) {
        throw ConfigurationError(path + "." + key + ": " + e.what());
    }
}
template <typename T>
T optional(const nlohmann::json& j, const char* key, T fallback, const std::string& path) {
    if (!j.contains(key))
        return fallback;
    try {
        return j.at(key).get<T>();
    } catch (const nlohmann::json::exception& e) {
        throw ConfigurationError(path + "." + key + ": " + e.what());
    }
}
std::filesystem::path program_data() {
    if (const char* value = std::getenv("ProgramData"))
        return std::filesystem::path(value);
    return L"C:\\ProgramData";
}

} // namespace

std::filesystem::path default_config_path() {
    return program_data() / "ScadaGuard" / "config.json";
}
std::filesystem::path default_state_database_path() {
    return program_data() / "ScadaGuard" / "state.db";
}

AppConfig load_config(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input)
        throw ConfigurationError("cannot open configuration file: " + path.string());
    try {
        nlohmann::json json;
        input >> json;
        auto config = parse_config(json);
        config.status.path = std::filesystem::absolute(path).string();
        return config;
    } catch (const ConfigurationError&) {
        throw;
    } catch (const nlohmann::json::exception& e) {
        throw ConfigurationError("invalid JSON: " + std::string(e.what()));
    }
}

AppConfig parse_config(const nlohmann::json& root) {
    if (!root.is_object())
        throw ConfigurationError("configuration root must be an object");
    AppConfig c;
    if (!root.contains("agent") || !root.at("agent").is_object())
        throw ConfigurationError("agent must be an object");
    const auto& a = root.at("agent");
    c.agent.agent_id = required<std::string>(a, "agent_id", "agent");
    c.agent.site_id = required<std::string>(a, "site_id", "agent");
    c.agent.host_id = required<std::string>(a, "host_id", "agent");
    c.agent.poll_interval_seconds = optional(a, "poll_interval_seconds", 30, "agent");
    c.agent.check_timeout_seconds = optional(a, "check_timeout_seconds", 10, "agent");
    c.agent.scheduler_worker_count = optional<std::size_t>(a, "scheduler_worker_count", 4, "agent");

    if (const auto it = root.find("logging"); it != root.end()) {
        c.logging.directory = optional(
            *it, "directory", (program_data() / "ScadaGuard" / "logs").string(), "logging");
        c.logging.level = optional(*it, "level", std::string("info"), "logging");
        c.logging.format = optional(*it, "format", std::string("text"), "logging");
        c.logging.max_file_size_mb = optional<std::size_t>(*it, "max_file_size_mb", 20, "logging");
        c.logging.max_files = optional<std::size_t>(*it, "max_files", 10, "logging");
    } else
        c.logging.directory = program_data() / "ScadaGuard" / "logs";
    if (const auto it = root.find("local_api"); it != root.end()) {
        c.local_api.enabled = optional(*it, "enabled", true, "local_api");
        c.local_api.bind_address =
            optional(*it, "bind_address", std::string("127.0.0.1"), "local_api");
        c.local_api.port = optional<std::uint16_t>(*it, "port", 9180, "local_api");
    }
    if (const auto it = root.find("central_server"); it != root.end()) {
        c.central_server.enabled = optional(*it, "enabled", false, "central_server");
        c.central_server.production = optional(*it, "production", true, "central_server");
        c.central_server.base_url = optional(*it, "base_url", std::string{}, "central_server");
        c.central_server.heartbeat_interval_seconds =
            optional(*it, "heartbeat_interval_seconds", 30, "central_server");
        c.central_server.request_timeout_seconds =
            optional(*it, "request_timeout_seconds", 10, "central_server");
        c.central_server.max_queue_size =
            optional<std::size_t>(*it, "max_queue_size", 10000, "central_server");
    }
    c.state_database = root.value("state_database", default_state_database_path().string());

    const auto parse_array = [&root](const char* name, const auto& callback) {
        if (!root.contains(name))
            return;
        if (!root.at(name).is_array())
            throw ConfigurationError(std::string(name) + " must be an array");
        std::size_t i = 0;
        for (const auto& item : root.at(name))
            callback(item, std::string(name) + "[" + std::to_string(i++) + "]");
    };
    parse_array("process_checks", [&](const auto& j, const std::string& p) {
        c.process_checks.push_back({required<std::string>(j, "id", p),
                                    required<std::string>(j, "process_name", p),
                                    optional(j, "required", true, p)});
    });
    parse_array("service_checks", [&](const auto& j, const std::string& p) {
        c.service_checks.push_back({required<std::string>(j, "id", p),
                                    required<std::string>(j, "service_name", p),
                                    optional(j, "required", true, p)});
    });
    parse_array("tcp_checks", [&](const auto& j, const std::string& p) {
        c.tcp_checks.push_back(
            {required<std::string>(j, "id", p), required<std::string>(j, "host", p),
             required<std::uint16_t>(j, "port", p), optional(j, "timeout_ms", 3000, p)});
    });
    parse_array("disk_checks", [&](const auto& j, const std::string& p) {
        c.disk_checks.push_back({required<std::string>(j, "id", p),
                                 required<std::string>(j, "path", p),
                                 optional(j, "warning_free_percent", 15.0, p),
                                 optional(j, "critical_free_percent", 7.0, p),
                                 optional(j, "critical_free_gb", 5.0, p)});
    });
    parse_array("file_activity_checks", [&](const auto& j, const std::string& p) {
        c.file_activity_checks.push_back({required<std::string>(j, "id", p),
                                          required<std::string>(j, "path", p),
                                          optional(j, "warning_unchanged_seconds", 300, p),
                                          optional(j, "critical_unchanged_seconds", 900, p),
                                          optional(j, "fail_on_shrink", true, p)});
    });
    parse_array("log_checks", [&](const auto& j, const std::string& p) {
        LogCheckConfig value{required<std::string>(j, "id", p),
                             required<std::string>(j, "path", p),
                             optional(j, "case_sensitive", false, p),
                             optional<std::size_t>(j, "max_read_bytes", 1048576, p),
                             {}};
        if (!j.contains("groups") || !j.at("groups").is_array())
            throw ConfigurationError(p + ".groups must be an array");
        std::size_t i = 0;
        for (const auto& g : j.at("groups")) {
            const auto gp = p + ".groups[" + std::to_string(i++) + "]";
            const auto severity_text = required<std::string>(g, "severity", gp);
            HealthStatus severity;
            try {
                severity = health_status_from_string(severity_text);
            } catch (const std::exception&) {
                throw ConfigurationError(gp + ".severity is invalid");
            }
            value.groups.push_back({required<std::string>(g, "name", gp), severity,
                                    required<std::vector<std::string>>(g, "patterns", gp)});
        }
        c.log_checks.push_back(std::move(value));
    });
    if (const auto it = root.find("data_sources"); it != root.end()) {
        for (const auto* name : {"current", "archive"})
            if (it->contains(name)) {
                auto& target =
                    std::string(name) == "current" ? c.current_data_source : c.archive_data_source;
                target.type = required<std::string>(it->at(name), "type",
                                                    std::string("data_sources.") + name);
                target.options = it->at(name);
            }
    }
    parse_array("signals", [&](const auto& j, const std::string& p) {
        SignalRule r;
        r.signal_id = required<std::string>(j, "signal_id", p);
        r.enabled = optional(j, "enabled", true, p);
        if (j.contains("minimum"))
            r.minimum = required<double>(j, "minimum", p);
        if (j.contains("maximum"))
            r.maximum = required<double>(j, "maximum", p);
        r.allowed_quality = optional(j, "allowed_quality", std::vector<std::string>{"Good"}, p);
        r.invalid_sentinels = optional(j, "invalid_sentinels", std::vector<double>{}, p);
        r.max_age_seconds = optional(j, "max_age_seconds", 60, p);
        if (j.contains("frozen_after_seconds"))
            r.frozen_after_seconds = required<int>(j, "frozen_after_seconds", p);
        r.frozen_epsilon = optional(j, "frozen_epsilon", 0.01, p);
        if (j.contains("max_rate_per_second"))
            r.max_rate_per_second = required<double>(j, "max_rate_per_second", p);
        if (j.contains("expected_period_seconds"))
            r.expected_period_seconds = required<int>(j, "expected_period_seconds", p);
        r.missing_period_multiplier = optional(j, "missing_period_multiplier", 3.0, p);
        r.archive_delay_seconds = optional(j, "archive_delay_seconds", 30, p);
        r.archive_match_window_seconds = optional(j, "archive_match_window_seconds", 10, p);
        r.archive_absolute_tolerance = optional(j, "archive_absolute_tolerance", 0.1, p);
        r.archive_relative_tolerance = optional(j, "archive_relative_tolerance", 0.001, p);
        c.signals.push_back(std::move(r));
    });
    const auto errors = validate_config(c);
    if (!errors.empty()) {
        std::ostringstream out;
        for (const auto& e : errors)
            out << e << '\n';
        throw ConfigurationError(out.str());
    }
    c.status.loaded = true;
    c.status.hash = configuration_hash(root);
    c.status.loaded_at = Clock::now();
    c.status.enabled_data_sources = {"current:" + c.current_data_source.type,
                                     "archive:" + c.archive_data_source.type};
    if (c.current_data_source.type == "mock") {
        c.status.unconfigured_subsystems.push_back("opcua");
    }
    if (c.archive_data_source.type == "mock" ||
        (c.archive_data_source.type == "sqlite" &&
         !c.archive_data_source.options.value("enabled", false))) {
        c.status.unconfigured_subsystems.push_back("archive");
    }
    return c;
}

std::string configuration_hash(const nlohmann::json& json) {
    const auto canonical = json.dump();
    std::uint64_t value = 14695981039346656037ull;
    for (const unsigned char byte : canonical) {
        value ^= byte;
        value *= 1099511628211ull;
    }
    std::ostringstream output;
    output << "fnv1a64-" << std::hex << std::setw(16) << std::setfill('0') << value;
    return output.str();
}

std::vector<std::string> validate_config(const AppConfig& c) {
    std::vector<std::string> e;
    const auto positive = [&e](auto value, const std::string& path) {
        if (value <= 0)
            e.push_back(path + " must be greater than zero");
    };
    if (c.agent.agent_id.empty())
        e.push_back("agent.agent_id must not be empty");
    if (c.agent.site_id.empty())
        e.push_back("agent.site_id must not be empty");
    if (c.agent.host_id.empty())
        e.push_back("agent.host_id must not be empty");
    positive(c.agent.poll_interval_seconds, "agent.poll_interval_seconds");
    positive(c.agent.check_timeout_seconds, "agent.check_timeout_seconds");
    positive(c.agent.scheduler_worker_count, "agent.scheduler_worker_count");
    if (c.logging.directory.empty())
        e.push_back("logging.directory must not be empty");
    if (std::set<std::string>{"trace", "debug", "info", "warn", "error", "critical", "off"}.count(
            c.logging.level) == 0)
        e.push_back("logging.level is invalid");
    if (c.logging.format != "text" && c.logging.format != "json")
        e.push_back("logging.format must be text or json");
    positive(c.logging.max_file_size_mb, "logging.max_file_size_mb");
    positive(c.logging.max_files, "logging.max_files");
    if (c.local_api.bind_address != "127.0.0.1")
        e.push_back("local_api.bind_address must be 127.0.0.1");
    positive(c.local_api.port, "local_api.port");
    if (c.central_server.enabled && c.central_server.base_url.empty())
        e.push_back("central_server.base_url is required when enabled");
    if (c.central_server.enabled && c.central_server.production &&
        !c.central_server.base_url.starts_with("https://"))
        e.push_back("central_server.base_url must use HTTPS in production");
    positive(c.central_server.heartbeat_interval_seconds,
             "central_server.heartbeat_interval_seconds");
    positive(c.central_server.request_timeout_seconds, "central_server.request_timeout_seconds");
    positive(c.central_server.max_queue_size, "central_server.max_queue_size");
    std::set<std::string> ids;
    const auto id = [&](const std::string& v, const std::string& p) {
        if (v.empty())
            e.push_back(p + ".id must not be empty");
        else if (!ids.insert(v).second)
            e.push_back(p + ".id must be unique");
    };
    for (std::size_t i = 0; i < c.process_checks.size(); ++i) {
        auto p = "process_checks[" + std::to_string(i) + "]";
        id(c.process_checks[i].id, p);
        if (c.process_checks[i].process_name.empty())
            e.push_back(p + ".process_name must not be empty");
    }
    for (std::size_t i = 0; i < c.service_checks.size(); ++i) {
        auto p = "service_checks[" + std::to_string(i) + "]";
        id(c.service_checks[i].id, p);
        if (c.service_checks[i].service_name.empty())
            e.push_back(p + ".service_name must not be empty");
    }
    for (std::size_t i = 0; i < c.tcp_checks.size(); ++i) {
        auto p = "tcp_checks[" + std::to_string(i) + "]";
        id(c.tcp_checks[i].id, p);
        if (c.tcp_checks[i].host.empty())
            e.push_back(p + ".host must not be empty");
        positive(c.tcp_checks[i].port, p + ".port");
        positive(c.tcp_checks[i].timeout_ms, p + ".timeout_ms");
    }
    for (std::size_t i = 0; i < c.disk_checks.size(); ++i) {
        auto p = "disk_checks[" + std::to_string(i) + "]";
        id(c.disk_checks[i].id, p);
        const auto& d = c.disk_checks[i];
        if (d.path.empty())
            e.push_back(p + ".path must not be empty");
        if (d.critical_free_percent < 0 || d.warning_free_percent > 100 ||
            d.critical_free_percent >= d.warning_free_percent)
            e.push_back(p + " thresholds must satisfy 0 <= critical_free_percent < "
                            "warning_free_percent <= 100");
        if (d.critical_free_gb < 0)
            e.push_back(p + ".critical_free_gb must be non-negative");
    }
    for (std::size_t i = 0; i < c.file_activity_checks.size(); ++i) {
        auto p = "file_activity_checks[" + std::to_string(i) + "]";
        id(c.file_activity_checks[i].id, p);
        if (c.file_activity_checks[i].path.empty())
            e.push_back(p + ".path must not be empty");
        positive(c.file_activity_checks[i].warning_unchanged_seconds,
                 p + ".warning_unchanged_seconds");
        positive(c.file_activity_checks[i].critical_unchanged_seconds,
                 p + ".critical_unchanged_seconds");
        if (c.file_activity_checks[i].critical_unchanged_seconds <
            c.file_activity_checks[i].warning_unchanged_seconds)
            e.push_back(p + " unchanged thresholds must be ordered");
    }
    for (std::size_t i = 0; i < c.log_checks.size(); ++i) {
        auto p = "log_checks[" + std::to_string(i) + "]";
        id(c.log_checks[i].id, p);
        if (c.log_checks[i].path.empty())
            e.push_back(p + ".path must not be empty");
        positive(c.log_checks[i].max_read_bytes, p + ".max_read_bytes");
        if (c.log_checks[i].groups.empty())
            e.push_back(p + ".groups must not be empty");
        for (std::size_t g = 0; g < c.log_checks[i].groups.size(); ++g)
            if (c.log_checks[i].groups[g].patterns.empty())
                e.push_back(p + ".groups[" + std::to_string(g) + "].patterns must not be empty");
    }
    if (c.current_data_source.type != "mock" && c.current_data_source.type != "csv" &&
        c.current_data_source.type != "opcua")
        e.push_back("data_sources.current.type must be mock, csv, or opcua");
    if (c.archive_data_source.type != "mock" && c.archive_data_source.type != "csv" &&
        c.archive_data_source.type != "sqlite")
        e.push_back("data_sources.archive.type must be mock, csv, or sqlite");
    if (c.current_data_source.type == "csv" &&
        c.current_data_source.options.value("path", std::string{}).empty())
        e.push_back("data_sources.current.path is required for csv");
    if (c.archive_data_source.type == "csv" &&
        c.archive_data_source.options.value("path", std::string{}).empty())
        e.push_back("data_sources.archive.path is required for csv");
    for (std::size_t i = 0; i < c.signals.size(); ++i) {
        auto p = "signals[" + std::to_string(i) + "]";
        const auto& r = c.signals[i];
        if (r.signal_id.empty())
            e.push_back(p + ".signal_id must not be empty");
        if (r.minimum && r.maximum && *r.maximum <= *r.minimum)
            e.push_back(p + ".maximum must be greater than " + p + ".minimum");
        positive(r.max_age_seconds, p + ".max_age_seconds");
        if (r.frozen_after_seconds)
            positive(*r.frozen_after_seconds, p + ".frozen_after_seconds");
        if (r.frozen_epsilon < 0)
            e.push_back(p + ".frozen_epsilon must be non-negative");
        if (r.max_rate_per_second)
            positive(*r.max_rate_per_second, p + ".max_rate_per_second");
        if (r.expected_period_seconds)
            positive(*r.expected_period_seconds, p + ".expected_period_seconds");
        positive(r.missing_period_multiplier, p + ".missing_period_multiplier");
        if (r.archive_delay_seconds < 0)
            e.push_back(p + ".archive_delay_seconds must be non-negative");
        positive(r.archive_match_window_seconds, p + ".archive_match_window_seconds");
        if (r.archive_absolute_tolerance < 0 || r.archive_relative_tolerance < 0)
            e.push_back(p + " archive tolerances must be non-negative");
        if (r.allowed_quality.empty())
            e.push_back(p + ".allowed_quality must not be empty");
    }
    return e;
}

} // namespace scadaguard
