#include "scadaguard/application.hpp"
#include "scadaguard/central_reporter.hpp"
#include "scadaguard/checks.hpp"
#include "scadaguard/data_quality.hpp"
#include "scadaguard/data_sources.hpp"
#include "scadaguard/http_server.hpp"
#include "scadaguard/incident_manager.hpp"
#include "scadaguard/local_storage.hpp"
#include "scadaguard/scheduler.hpp"
#include <condition_variable>
#include <mutex>
#include <thread>

namespace scadaguard {
namespace {
std::unique_ptr<ICurrentDataSource> make_current_source(const DataSourceConfig& config) {
    if (config.type == "mock")
        return std::make_unique<MockCurrentDataSource>();
    if (config.type == "csv")
        return std::make_unique<CsvReplayDataSource>(config.options.at("path").get<std::string>());
    if (config.type == "opcua")
        return std::make_unique<OpcUaCurrentDataSource>();
    throw ConfigurationError("data_sources.current.type is unsupported: " + config.type);
}
std::unique_ptr<IArchiveDataSource> make_archive_source(const DataSourceConfig& config) {
    if (config.type == "mock")
        return std::make_unique<MockArchiveDataSource>();
    if (config.type == "csv")
        return std::make_unique<CsvReplayDataSource>(config.options.at("path").get<std::string>());
    if (config.type == "sqlite")
        return std::make_unique<SqliteArchiveDataSource>(
            SqliteArchiveOptions{config.options.value("enabled", false),
                                 config.options.value("database_path", std::string{}),
                                 config.options.value("table", std::string{}),
                                 config.options.value("signal_id_column", std::string{}),
                                 config.options.value("timestamp_column", std::string{}),
                                 config.options.value("value_column", std::string{}),
                                 config.options.value("quality_column", std::string{})});
    throw ConfigurationError("data_sources.archive.type is unsupported: " + config.type);
}
} // namespace
struct Application::Impl {
    AppConfig config;
    CheckScheduler scheduler;
    DataQualityAnalyzer quality;
    LocalStorage storage;
    IncidentManager incidents;
    std::string boot_id;
    std::shared_ptr<AgentState> state;
    std::unique_ptr<LocalHttpServer> http;
    std::unique_ptr<ICurrentDataSource> current;
    std::unique_ptr<IArchiveDataSource> archive;
    std::unique_ptr<ICentralReporter> reporter;
    TimePoint last_heartbeat{};
    nlohmann::json make_message(std::string kind, nlohmann::json payload) {
        return {{"message_id", generate_uuid_v4()},
                {"protocol_version", 1},
                {"message_kind", std::move(kind)},
                {"agent_id", config.agent.agent_id},
                {"site_id", config.agent.site_id},
                {"host_id", config.agent.host_id},
                {"boot_id", boot_id},
                {"sequence_number", storage.next_sequence_number()},
                {"created_at", format_utc(Clock::now())},
                {"payload", std::move(payload)}};
    }
    explicit Impl(AppConfig c)
        : config(std::move(c)), scheduler(config.agent.scheduler_worker_count),
          storage(config.state_database),
          incidents(config.agent.site_id, config.agent.host_id, {}, storage.load_incidents()),
          boot_id(storage.start_new_boot()),
          state(std::make_shared<AgentState>(config.agent, config.status, boot_id)) {
        for (auto& v : config.process_checks)
            scheduler.add(std::make_shared<ProcessCheck>(v));
        for (auto& v : config.service_checks)
            scheduler.add(std::make_shared<WindowsServiceCheck>(v));
        for (auto& v : config.tcp_checks)
            scheduler.add(std::make_shared<TcpPortCheck>(v));
        for (auto& v : config.disk_checks)
            scheduler.add(std::make_shared<DiskSpaceCheck>(v));
        for (auto& v : config.file_activity_checks)
            scheduler.add(std::make_shared<FileActivityCheck>(v, &storage));
        for (auto& v : config.log_checks)
            scheduler.add(std::make_shared<LogPatternCheck>(v, &storage));
        current = make_current_source(config.current_data_source);
        archive = make_archive_source(config.archive_data_source);
        http = std::make_unique<LocalHttpServer>(config.local_api, state);
        if (config.central_server.enabled)
            reporter = std::make_unique<HttpCentralReporter>(config.central_server, storage);
        else
            reporter = std::make_unique<DisabledCentralReporter>();
        quality.restore_history(storage.load_signal_history());
        state->update(storage.load_checks(), incidents.incidents(), storage.load_signal_history(),
                      storage.pending_event_count(), storage.oldest_pending_event_at());
    }
    nlohmann::json cycle(std::stop_token stop) {
        auto results =
            scheduler.run_once(std::chrono::seconds(config.agent.check_timeout_seconds), stop);
        std::vector<SignalSample> online;
        try {
            online = current->read_current(stop);
            for (const auto& sample : online) {
                storage.save_signal_history(sample);
            }
            auto q = quality.analyze(online, config.signals, Clock::now());
            results.insert(results.end(), q.begin(), q.end());
            if (!online.empty()) {
                auto from = online.front().source_timestamp - std::chrono::seconds(60);
                auto archived = archive->read_archive(from, Clock::now(), stop);
                auto comparisons =
                    quality.compare_archive(online, archived, config.signals, Clock::now());
                results.insert(results.end(), comparisons.begin(), comparisons.end());
            }
        } catch (const std::exception& e) {
            results.push_back({"data-source",
                               "data-source",
                               HealthStatus::Unknown,
                               e.what(),
                               Clock::now(),
                               {{"problem_type", "data_source_error"}}});
        }
        nlohmann::json incident_events = nlohmann::json::array();
        for (const auto& r : results) {
            storage.save_check(r);
            for (const auto& e : incidents.process(r, r.observed_at)) {
                storage.save_incident(e.incident);
                incident_events.push_back({{"type", e.type},
                                           {"occurred_at", format_utc(e.occurred_at)},
                                           {"incident", e.incident}});
            }
        }
        auto all = incidents.incidents();
        state->update(results, all, online, storage.pending_event_count(),
                      storage.oldest_pending_event_at());
        const auto now = Clock::now();
        if (config.central_server.enabled) {
            reporter->send_check_results(make_message("check_results", {{"items", results}}), stop);
            if (!incident_events.empty()) {
                reporter->send_incidents(
                    make_message("incidents", {{"items", std::move(incident_events)}}), stop);
            }
            if (!online.empty()) {
                reporter->send_signal_samples(make_message("signal_samples", {{"items", online}}),
                                              stop);
            }
            if (last_heartbeat == TimePoint{} ||
                now - last_heartbeat >=
                    std::chrono::seconds(config.central_server.heartbeat_interval_seconds)) {
                reporter->send_heartbeat(make_message("heartbeat", state->health()), stop);
                last_heartbeat = now;
            }
        }
        return {{"health", state->health()}, {"checks", results}, {"incidents", all}};
    }
};
Application::Application(AppConfig c) : impl_(std::make_unique<Impl>(std::move(c))) {}
Application::~Application() = default;
nlohmann::json Application::run_once(std::stop_token stop) {
    return impl_->cycle(stop);
}
void Application::run(std::stop_token stop) {
    impl_->http->start();
    while (!stop.stop_requested()) {
        impl_->cycle(stop);
        std::mutex m;
        std::condition_variable_any cv;
        std::unique_lock lock(m);
        cv.wait_for(lock, stop, std::chrono::seconds(impl_->config.agent.poll_interval_seconds),
                    [] { return false; });
    }
    impl_->http->stop();
}
} // namespace scadaguard
