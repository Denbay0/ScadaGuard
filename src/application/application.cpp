#include "scadaguard/application.hpp"
#include "scadaguard/central_reporter.hpp"
#include "scadaguard/central_configuration.hpp"
#include "scadaguard/checks.hpp"
#include "scadaguard/data_quality.hpp"
#include "scadaguard/data_sources.hpp"
#include "scadaguard/discovery.hpp"
#include "scadaguard/http_server.hpp"
#include "scadaguard/incident_manager.hpp"
#include "scadaguard/local_storage.hpp"
#include "scadaguard/scheduler.hpp"
#include "scadaguard/windows_discovery.hpp"
#include <condition_variable>
#include <mutex>
#include <ranges>
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
                                 config.options.value("quality_column", std::string{}),
                                 config.options.value("maximum_batch_size", std::size_t{5'000})});
    throw ConfigurationError("data_sources.archive.type is unsupported: " + config.type);
}
DiscoveryHints make_discovery_hints(const DiscoveryConfig& config) {
    DiscoveryHints hints;
    hints.keywords = config.keywords;
    hints.additional_roots = config.additional_roots;
    hints.relative_log_directories = config.relative_log_directories;
    hints.limits.maximum_directories = config.maximum_directories;
    hints.limits.maximum_files = config.maximum_files;
    hints.limits.maximum_depth = config.maximum_depth;
    hints.limits.maximum_duration = std::chrono::seconds(config.maximum_duration_seconds);
    hints.limits.maximum_inspected_bytes = config.maximum_inspected_bytes;
    return hints;
}
void apply_archive_mapping(AppConfig& config, const DesiredAgentConfiguration& desired) {
    if (desired.archive_mapping.is_null() || desired.archive_mapping.empty()) {
        return;
    }
    config.archive_data_source.type = "sqlite";
    config.archive_data_source.options = desired.archive_mapping;
    config.archive_data_source.options["enabled"] = true;
    config.archive_data_source.options["database_path"] = desired.confirmed_archive->string();
    if (config.archive_data_source.options.value("quality_column", nlohmann::json{}).is_null()) {
        config.archive_data_source.options["quality_column"] = "";
    }
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
    WindowsDiscoveryEnvironment discovery_environment;
    std::unique_ptr<MasterScadaDiscovery> discovery;
    std::mutex discovery_mutex;
    TimePoint last_discovery{};
    TimePoint last_configuration_poll{};
    std::uint64_t applied_configuration_version{};
    std::string last_rescan_request;
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
        if (const auto working = storage.load_working_central_configuration()) {
            try {
                const auto desired = validate_desired_agent_configuration(*working);
                auto candidate = config;
                candidate.agent.poll_interval_seconds = desired.monitoring_interval_seconds;
                apply_archive_mapping(candidate, desired);
                if (desired.server_url)
                    candidate.central_server.base_url = *desired.server_url;
                if (!desired.monitored_signals.empty()) {
                    for (auto& signal : candidate.signals) {
                        signal.enabled =
                            std::ranges::find(desired.monitored_signals, signal.signal_id) !=
                            desired.monitored_signals.end();
                    }
                }
                for (const auto& [signal_id, thresholds] : desired.thresholds.items()) {
                    auto signal = std::ranges::find_if(candidate.signals, [&](const auto& item) {
                        return item.signal_id == signal_id;
                    });
                    if (signal == candidate.signals.end())
                        throw ConfigurationError("persisted threshold references unknown signal");
                    if (thresholds.contains("minimum") && !thresholds.at("minimum").is_null())
                        signal->minimum = thresholds.at("minimum").get<double>();
                    if (thresholds.contains("maximum") && !thresholds.at("maximum").is_null())
                        signal->maximum = thresholds.at("maximum").get<double>();
                    if (thresholds.contains("max_rate_per_second") &&
                        !thresholds.at("max_rate_per_second").is_null())
                        signal->max_rate_per_second =
                            thresholds.at("max_rate_per_second").get<double>();
                }
                if (const auto errors = validate_config(candidate); !errors.empty())
                    throw ConfigurationError(errors.front());
                config = std::move(candidate);
                config.discovery.confirmed_archive = desired.confirmed_archive;
                config.discovery.confirmed_logs = desired.confirmed_logs;
                config.archive_data_source = std::move(candidate.archive_data_source);
                applied_configuration_version = desired.version;
                last_rescan_request = desired.rescan_requested_at.value_or("");
            } catch (const std::exception&) {
                config.status.warnings.push_back(
                    "persisted central configuration is invalid; local configuration retained");
            }
        }
        archive = make_archive_source(config.archive_data_source);
        if (config.central_server.enabled)
            reporter = std::make_unique<HttpCentralReporter>(config.central_server, storage);
        else
            reporter = std::make_unique<DisabledCentralReporter>();
        if (config.discovery.enabled) {
            discovery = std::make_unique<MasterScadaDiscovery>(
                discovery_environment, make_discovery_hints(config.discovery));
        }
        if (const auto persisted = storage.load_discovery_report()) {
            state->update_discovery(*persisted);
        }
        http = std::make_unique<LocalHttpServer>(
            config.local_api, state,
            discovery ? std::function<nlohmann::json()>([this] { return perform_discovery({}); })
                      : std::function<nlohmann::json()>{});
        quality.restore_history(storage.load_signal_history());
        state->update(storage.load_checks(), incidents.incidents(), storage.load_signal_history(),
                      storage.pending_event_count(), storage.oldest_pending_event_at());
    }
    nlohmann::json perform_discovery(std::stop_token stop) {
        std::scoped_lock lock(discovery_mutex);
        if (!discovery) {
            return {{"masterscada", {{"detected", false}, {"status", "unsupported"}}},
                    {"warnings", {"discovery is disabled"}}};
        }
        DiscoverySelection selection;
        selection.confirmed_archive = config.discovery.confirmed_archive;
        selection.confirmed_logs = config.discovery.confirmed_logs;
        if (!selection.confirmed_archive && config.archive_data_source.type == "sqlite" &&
            config.archive_data_source.options.value("enabled", false)) {
            const auto path =
                config.archive_data_source.options.value("database_path", std::string{});
            if (!path.empty())
                selection.configured_archive = path;
        }
        nlohmann::json report = discovery->scan(selection, stop);
        report["agent_id"] = config.agent.agent_id;
        storage.save_discovery_report(report);
        state->update_discovery(report);
        last_discovery = Clock::now();
        if (config.central_server.enabled) {
            reporter->send_discovery(make_message("discovery", report), stop);
        }
        return report;
    }
    void poll_central_configuration(std::stop_token stop) {
        if (!config.central_server.enabled ||
            (last_configuration_poll != TimePoint{} &&
             Clock::now() - last_configuration_poll <
                 std::chrono::seconds(config.central_server.heartbeat_interval_seconds))) {
            return;
        }
        last_configuration_poll = Clock::now();
        const auto response = reporter->fetch_configuration(stop);
        if (!response || response->value("config_version", std::uint64_t{}) == 0) {
            return;
        }
        const auto requested_version = response->value("config_version", std::uint64_t{});
        if (requested_version <= applied_configuration_version) {
            return;
        }
        try {
            const auto desired = validate_desired_agent_configuration(*response);
            std::error_code error;
            if (desired.confirmed_archive &&
                !std::filesystem::is_regular_file(*desired.confirmed_archive, error)) {
                throw ConfigurationError("confirmed archive does not exist or is not a file");
            }
            for (const auto& path : desired.confirmed_logs) {
                error.clear();
                if (!std::filesystem::is_regular_file(path, error)) {
                    throw ConfigurationError("confirmed log does not exist or is not a file: " +
                                             path.string());
                }
            }
            auto candidate = config;
            candidate.agent.poll_interval_seconds = desired.monitoring_interval_seconds;
            apply_archive_mapping(candidate, desired);
            if (desired.server_url) {
                candidate.central_server.base_url = *desired.server_url;
            }
            if (!desired.monitored_signals.empty()) {
                for (const auto& signal_id : desired.monitored_signals) {
                    if (std::ranges::none_of(candidate.signals, [&](const auto& signal) {
                            return signal.signal_id == signal_id;
                        })) {
                        throw ConfigurationError(
                            "central configuration references unknown signal: " + signal_id);
                    }
                }
                for (auto& signal : candidate.signals) {
                    signal.enabled =
                        std::ranges::find(desired.monitored_signals, signal.signal_id) !=
                        desired.monitored_signals.end();
                }
            }
            for (const auto& [signal_id, thresholds] : desired.thresholds.items()) {
                auto signal = std::ranges::find_if(candidate.signals, [&](const auto& item) {
                    return item.signal_id == signal_id;
                });
                if (signal == candidate.signals.end()) {
                    throw ConfigurationError("threshold references unknown signal: " + signal_id);
                }
                if (thresholds.contains("minimum") && !thresholds.at("minimum").is_null())
                    signal->minimum = thresholds.at("minimum").get<double>();
                if (thresholds.contains("maximum") && !thresholds.at("maximum").is_null())
                    signal->maximum = thresholds.at("maximum").get<double>();
                if (thresholds.contains("max_rate_per_second") &&
                    !thresholds.at("max_rate_per_second").is_null())
                    signal->max_rate_per_second =
                        thresholds.at("max_rate_per_second").get<double>();
            }
            const auto validation_errors = validate_config(candidate);
            if (!validation_errors.empty()) {
                throw ConfigurationError("central configuration is invalid: " +
                                         validation_errors.front());
            }
            const bool rescan_requested =
                desired.rescan_requested_at.value_or("") != last_rescan_request;
            const bool server_changed =
                candidate.central_server.base_url != config.central_server.base_url;
            {
                std::scoped_lock lock(discovery_mutex);
                config.agent.poll_interval_seconds = candidate.agent.poll_interval_seconds;
                config.signals = std::move(candidate.signals);
                config.central_server.base_url = candidate.central_server.base_url;
                config.archive_data_source = std::move(candidate.archive_data_source);
                config.discovery.confirmed_archive = desired.confirmed_archive;
                config.discovery.confirmed_logs = desired.confirmed_logs;
                storage.save_working_central_configuration(desired.raw);
                applied_configuration_version = desired.version;
                last_rescan_request = desired.rescan_requested_at.value_or("");
            }
            archive = make_archive_source(config.archive_data_source);
            if (server_changed) {
                reporter = std::make_unique<HttpCentralReporter>(config.central_server, storage);
            }
            reporter->send_configuration_status(
                {{"config_version", desired.version},
                 {"status", "applied"},
                 {"message", "validated and activated for ScadaGuard read-only monitoring"}},
                stop);
            if (desired.confirmed_archive || rescan_requested) {
                perform_discovery(stop);
            }
        } catch (const std::exception& error) {
            reporter->send_configuration_status({{"config_version", requested_version},
                                                 {"status", "rejected"},
                                                 {"message", error.what()}},
                                                stop);
        }
    }
    nlohmann::json cycle(std::stop_token stop) {
        poll_central_configuration(stop);
        const auto now = Clock::now();
        if (discovery && (last_discovery == TimePoint{} ||
                          now - last_discovery >=
                              std::chrono::hours(config.discovery.scheduled_interval_hours))) {
            perform_discovery(stop);
        }
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
        const auto reporting_now = Clock::now();
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
                reporting_now - last_heartbeat >=
                    std::chrono::seconds(config.central_server.heartbeat_interval_seconds)) {
                reporter->send_heartbeat(make_message("heartbeat", state->health()), stop);
                last_heartbeat = reporting_now;
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
