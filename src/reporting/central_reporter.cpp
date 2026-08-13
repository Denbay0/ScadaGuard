#include "scadaguard/central_reporter.hpp"
#include "scadaguard/environment.hpp"
#include <algorithm>
#include <httplib.h>
#include <stdexcept>

namespace scadaguard {
HttpCentralReporter::HttpCentralReporter(CentralServerConfig c, LocalStorage& s)
    : config_(std::move(c)), storage_(s) {
    if (config_.production && !config_.base_url.starts_with("https://"))
        throw std::invalid_argument("central server requires HTTPS in production");
}
bool HttpCentralReporter::send(const char* path, const nlohmann::json& body, std::stop_token stop) {
    if (stop.stop_requested())
        return false;
    const auto token = environment_variable("SCADAGUARD_API_TOKEN");
    if (!token)
        return false;
    httplib::Client client(config_.base_url);
    client.set_connection_timeout(config_.request_timeout_seconds);
    client.set_read_timeout(config_.request_timeout_seconds);
    httplib::Headers headers{{"Authorization", "Bearer " + *token}};
    const auto response = client.Post(path, headers, body.dump(), "application/json");
    return response && response->status >= 200 && response->status < 300;
}
std::optional<nlohmann::json> HttpCentralReporter::get(const char* path, std::stop_token stop) {
    if (stop.stop_requested())
        return std::nullopt;
    const auto token = environment_variable("SCADAGUARD_API_TOKEN");
    if (!token)
        return std::nullopt;
    httplib::Client client(config_.base_url);
    client.set_connection_timeout(config_.request_timeout_seconds);
    client.set_read_timeout(config_.request_timeout_seconds);
    httplib::Headers headers{{"Authorization", "Bearer " + *token}};
    const auto response = client.Get(path, headers);
    if (!response || response->status < 200 || response->status >= 300)
        return std::nullopt;
    try {
        return nlohmann::json::parse(response->body);
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }
}
bool HttpCentralReporter::send_heartbeat(const nlohmann::json& v, std::stop_token stop) {
    const bool sent = send_or_queue("/api/v1/agent/heartbeat", v, stop);
    if (sent)
        flush(stop);
    return sent;
}
bool HttpCentralReporter::send_or_queue(const char* path, const nlohmann::json& value,
                                        std::stop_token stop) {
    if (send(path, value, stop))
        return true;
    storage_.enqueue_event({{"delivery_path", path}, {"body", value}}, config_.max_queue_size);
    return false;
}
bool HttpCentralReporter::send_check_results(const nlohmann::json& value, std::stop_token stop) {
    return send_or_queue("/api/v1/agent/check-results/batch", value, stop);
}
bool HttpCentralReporter::send_incidents(const nlohmann::json& value, std::stop_token stop) {
    return send_or_queue("/api/v1/agent/incidents/batch", value, stop);
}
bool HttpCentralReporter::send_signal_samples(const nlohmann::json& value, std::stop_token stop) {
    return send_or_queue("/api/v1/agent/signal-samples/batch", value, stop);
}
bool HttpCentralReporter::send_discovery(const nlohmann::json& value, std::stop_token stop) {
    return send_or_queue("/api/v1/agent/discovery", value, stop);
}
std::optional<nlohmann::json> HttpCentralReporter::fetch_configuration(std::stop_token stop) {
    return get("/api/v1/agent/config", stop);
}
bool HttpCentralReporter::send_configuration_status(const nlohmann::json& value,
                                                     std::stop_token stop) {
    return send_or_queue("/api/v1/agent/config/status", value, stop);
}
std::size_t HttpCentralReporter::flush(std::stop_token stop) {
    const auto now = std::chrono::steady_clock::now();
    if (now < next_retry_)
        return 0;
    std::size_t sent = 0;
    for (const auto& [id, event] : storage_.pending_events(100)) {
        if (stop.stop_requested())
            break;
        const auto path = event.value("delivery_path", std::string{});
        if (path.empty() || !event.contains("body") ||
            !send(path.c_str(), event.at("body"), stop)) {
            retry_attempt_ = std::min(retry_attempt_ + 1, 8u);
            const auto retry_delay = std::chrono::seconds(1u << retry_attempt_);
            storage_.mark_event_failed(id, retry_delay);
            next_retry_ = now + retry_delay;
            break;
        }
        storage_.mark_event_sent(id);
        ++sent;
        retry_attempt_ = 0;
        next_retry_ = {};
    }
    return sent;
}
} // namespace scadaguard
