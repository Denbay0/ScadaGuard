#include "scadaguard/http_server.hpp"

#include "scadaguard/version.hpp"

#include <httplib.h>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <sstream>
#include <stdexcept>

namespace scadaguard {
namespace {

int status_rank(const HealthStatus status) {
    switch (status) {
    case HealthStatus::Ok:
        return 0;
    case HealthStatus::Warning:
        return 1;
    case HealthStatus::Critical:
        return 2;
    case HealthStatus::Unknown:
        return 3;
    }
    return 3;
}

int metric_status(const HealthStatus status) {
    return status_rank(status);
}

std::string escape_prometheus_label(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        switch (character) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\n':
            escaped += "\\n";
            break;
        default:
            escaped += character;
            break;
        }
    }
    return escaped;
}

std::string hostname() {
    std::array<char, MAX_COMPUTERNAME_LENGTH + 1> buffer{};
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!GetComputerNameA(buffer.data(), &size)) {
        return "unknown";
    }
    return std::string(buffer.data(), size);
}

std::string windows_version() {
    const auto module = GetModuleHandleW(L"ntdll.dll");
    if (!module) {
        return "unknown";
    }
    using RtlGetVersionFunction = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const auto function =
        reinterpret_cast<RtlGetVersionFunction>(GetProcAddress(module, "RtlGetVersion"));
    if (!function) {
        return "unknown";
    }
    RTL_OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (function(&version) != 0) {
        return "unknown";
    }
    return std::to_string(version.dwMajorVersion) + "." + std::to_string(version.dwMinorVersion) +
           "." + std::to_string(version.dwBuildNumber);
}

} // namespace

AgentState::AgentState(AgentConfig agent, ConfigurationStatus configuration, std::string boot_id)
    : agent_(std::move(agent)), configuration_(std::move(configuration)),
      boot_id_(std::move(boot_id)), hostname_(hostname()), windows_version_(windows_version()),
      started_(Clock::now()) {}

void AgentState::update(std::vector<CheckResult> checks, std::vector<Incident> incidents,
                        std::vector<SignalSample> signals, const std::size_t queue_size,
                        std::optional<TimePoint> oldest_queued_at) {
    std::scoped_lock lock(mutex_);
    checks_ = std::move(checks);
    incidents_ = std::move(incidents);
    signals_ = std::move(signals);
    queue_size_ = queue_size;
    oldest_queued_at_ = oldest_queued_at;
}

nlohmann::json AgentState::health() const {
    std::scoped_lock lock(mutex_);
    HealthStatus status = checks_.empty() ? HealthStatus::Unknown : HealthStatus::Ok;
    for (const auto& check : checks_) {
        if (status_rank(check.status) > status_rank(status)) {
            status = check.status;
        }
    }
    if (!configuration_.unconfigured_subsystems.empty() && status == HealthStatus::Ok) {
        status = HealthStatus::Unknown;
    }
    const auto active =
        std::ranges::count_if(incidents_, [](const auto& incident) { return incident.active; });
    return {{"agent_id", agent_.agent_id},
            {"site_id", agent_.site_id},
            {"host_id", agent_.host_id},
            {"status", status},
            {"started_at", format_utc(started_)},
            {"observed_at", format_utc(Clock::now())},
            {"active_incidents", active},
            {"agent_version", std::string(agent_version)},
            {"protocol_version", protocol_version},
            {"boot_id", boot_id_},
            {"runtime_mode", agent_.runtime_mode},
            {"hostname", hostname_},
            {"windows_version", windows_version_},
            {"uptime_seconds",
             std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - started_).count()},
            {"build_type", std::string(build_type)},
            {"architecture", std::string(build_architecture)},
            {"configuration_hash", configuration_.hash},
            {"queue_size", queue_size_}};
}

nlohmann::json AgentState::checks() const {
    std::scoped_lock lock(mutex_);
    return checks_;
}

nlohmann::json AgentState::incidents() const {
    std::scoped_lock lock(mutex_);
    return incidents_;
}

nlohmann::json AgentState::signals() const {
    std::scoped_lock lock(mutex_);
    return signals_;
}

nlohmann::json AgentState::configuration_status() const {
    std::scoped_lock lock(mutex_);
    return {{"loaded", configuration_.loaded},
            {"path", configuration_.path},
            {"hash", configuration_.hash},
            {"warning_count", configuration_.warnings.size()},
            {"warnings", configuration_.warnings},
            {"enabled_data_sources", configuration_.enabled_data_sources},
            {"unconfigured_subsystems", configuration_.unconfigured_subsystems},
            {"last_successful_load_at", format_utc(configuration_.loaded_at)}};
}

nlohmann::json AgentState::queue_status() const {
    std::scoped_lock lock(mutex_);
    nlohmann::json result{{"pending_messages", queue_size_}};
    result["oldest_message_at"] = oldest_queued_at_ ? nlohmann::json(format_utc(*oldest_queued_at_))
                                                    : nlohmann::json(nullptr);
    if (oldest_queued_at_) {
        result["oldest_message_age_seconds"] =
            std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - *oldest_queued_at_)
                .count();
    }
    return result;
}

nlohmann::json AgentState::version() const {
    return {{"agent_version", std::string(agent_version)},
            {"protocol_version", protocol_version},
            {"build_type", std::string(build_type)},
            {"architecture", std::string(build_architecture)}};
}

std::string AgentState::metrics() const {
    std::scoped_lock lock(mutex_);
    std::ostringstream output;
    output << "# HELP scadaguard_check_status Check status: 0 ok, 1 warning, 2 critical, 3 "
              "unknown\n"
              "# TYPE scadaguard_check_status gauge\n";
    for (const auto& check : checks_) {
        output << "scadaguard_check_status{check_id=\"" << escape_prometheus_label(check.check_id)
               << "\",component=\"" << escape_prometheus_label(check.component) << "\"} "
               << metric_status(check.status) << '\n';
    }
    output << "# TYPE scadaguard_active_incidents gauge\nscadaguard_active_incidents "
           << std::ranges::count_if(incidents_,
                                    [](const auto& incident) { return incident.active; })
           << '\n';
    output << "# TYPE scadaguard_outbound_queue_size gauge\nscadaguard_outbound_queue_size "
           << queue_size_ << '\n';
    if (oldest_queued_at_) {
        output << "# TYPE scadaguard_outbound_queue_oldest_age_seconds gauge\n"
                  "scadaguard_outbound_queue_oldest_age_seconds "
               << std::max<std::int64_t>(0, std::chrono::duration_cast<std::chrono::seconds>(
                                                Clock::now() - *oldest_queued_at_)
                                                .count())
               << '\n';
    }
    return output.str();
}

LocalHttpServer::LocalHttpServer(LocalApiConfig config, std::shared_ptr<AgentState> state)
    : config_(std::move(config)), state_(std::move(state)),
      server_(std::make_unique<httplib::Server>()) {
    if (config_.bind_address != "127.0.0.1") {
        throw std::invalid_argument("local API may only bind to 127.0.0.1");
    }
    server_->Get("/api/v1/health", [this](const auto&, auto& response) {
        response.set_content(state_->health().dump(), "application/json");
    });
    server_->Get("/api/v1/checks", [this](const auto&, auto& response) {
        response.set_content(state_->checks().dump(), "application/json");
    });
    server_->Get("/api/v1/incidents", [this](const auto&, auto& response) {
        response.set_content(state_->incidents().dump(), "application/json");
    });
    server_->Get("/api/v1/signals", [this](const auto&, auto& response) {
        response.set_content(state_->signals().dump(), "application/json");
    });
    server_->Get("/api/v1/config/status", [this](const auto&, auto& response) {
        response.set_content(state_->configuration_status().dump(), "application/json");
    });
    server_->Get("/api/v1/queue/status", [this](const auto&, auto& response) {
        response.set_content(state_->queue_status().dump(), "application/json");
    });
    server_->Get("/api/v1/version", [this](const auto&, auto& response) {
        response.set_content(state_->version().dump(), "application/json");
    });
    server_->Get("/metrics", [this](const auto&, auto& response) {
        response.set_content(state_->metrics(), "text/plain; version=0.0.4");
    });
}

LocalHttpServer::~LocalHttpServer() {
    stop();
}

void LocalHttpServer::start() {
    if (thread_.joinable() || !config_.enabled) {
        return;
    }
    if (server_->bind_to_port(config_.bind_address, config_.port) <= 0) {
        throw std::runtime_error("cannot bind local API to " + config_.bind_address + ":" +
                                 std::to_string(config_.port));
    }
    thread_ = std::jthread([this] { server_->listen_after_bind(); });
}

void LocalHttpServer::stop() {
    if (server_) {
        server_->stop();
    }
    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }
}

} // namespace scadaguard
