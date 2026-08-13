#pragma once

#include "scadaguard/checks.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

struct sqlite3;

namespace scadaguard {

class LocalStorage : public ICheckStateStore {
  public:
    explicit LocalStorage(const std::filesystem::path& path);
    ~LocalStorage();
    LocalStorage(const LocalStorage&) = delete;
    LocalStorage& operator=(const LocalStorage&) = delete;

    int schema_version() const;

    void save_check(const CheckResult& result);
    std::vector<CheckResult> load_checks() const;

    void save_incident(const Incident& incident);
    std::vector<Incident> load_incidents() const;

    void save_log_state(const LogCheckState& state) override;
    std::optional<LogCheckState> load_log_state(const std::string& check_id) const override;
    void save_file_state(const FileCheckState& state) override;
    std::optional<FileCheckState> load_file_state(const std::string& check_id) const override;

    void save_signal_history(const SignalSample& sample);
    std::vector<SignalSample> load_signal_history() const;

    std::string start_new_boot();
    std::uint64_t next_sequence_number();

    void enqueue_event(const nlohmann::json& event, std::size_t max_size);
    std::vector<std::pair<std::int64_t, nlohmann::json>> pending_events(std::size_t limit) const;
    void mark_event_sent(std::int64_t id);
    void mark_event_failed(std::int64_t id, std::chrono::seconds retry_delay);
    std::size_t pending_event_count() const;
    std::optional<TimePoint> oldest_pending_event_at() const;

    void save_discovery_report(const nlohmann::json& report);
    std::optional<nlohmann::json> load_discovery_report() const;
    void save_working_central_configuration(const nlohmann::json& configuration);
    std::optional<nlohmann::json> load_working_central_configuration() const;
    std::optional<nlohmann::json> load_previous_central_configuration() const;

  private:
    void execute_unlocked(const char* sql) const;
    int schema_version_unlocked() const;
    void migrate();
    void migrate_1_to_2();
    void migrate_2_to_3();
    void migrate_3_to_4();

    sqlite3* db_{};
    mutable std::mutex mutex_;
};

} // namespace scadaguard
