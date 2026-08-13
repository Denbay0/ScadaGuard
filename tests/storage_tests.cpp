#include "scadaguard/incident_manager.hpp"
#include "scadaguard/local_storage.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

using namespace scadaguard;
using namespace std::chrono_literals;

namespace {

class TemporaryDatabase {
  public:
    TemporaryDatabase()
        : path_(std::filesystem::temp_directory_path() /
                ("scadaguard-test-" + generate_uuid_v4() + ".db")) {}

    ~TemporaryDatabase() {
        std::error_code error;
        std::filesystem::remove(path_, error);
        std::filesystem::remove(path_.string() + "-wal", error);
        std::filesystem::remove(path_.string() + "-shm", error);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

const auto observed_at = parse_utc("2026-08-05T10:00:00Z");

CheckResult critical_result() {
    return {"disk",      "disk",      HealthStatus::Critical,
            "low space", observed_at, {{"problem_type", "space"}}};
}

} // namespace

TEST_CASE("local storage migrates a new database to the latest schema") {
    TemporaryDatabase database;
    LocalStorage storage(database.path());
    REQUIRE(storage.schema_version() == 4);
}

TEST_CASE("discovery report survives reopening") {
    TemporaryDatabase database;
    {
        LocalStorage storage(database.path());
        storage.save_discovery_report({{"scan_id", "scan-1"}, {"masterscada", {{"detected", true}}}});
    }
    {
        LocalStorage storage(database.path());
        const auto report = storage.load_discovery_report();
        REQUIRE(report.has_value());
        REQUIRE(report->at("scan_id") == "scan-1");
        REQUIRE(report->at("masterscada").at("detected") == true);
    }
}

TEST_CASE("central configuration activation retains the previous working version") {
    TemporaryDatabase database;
    LocalStorage storage(database.path());
    storage.save_working_central_configuration({{"config_version", 1}});
    storage.save_working_central_configuration({{"config_version", 2}});
    REQUIRE(storage.load_working_central_configuration()->at("config_version") == 2);
    REQUIRE(storage.load_previous_central_configuration()->at("config_version") == 1);
}

TEST_CASE("check, log, file, and signal state survives reopening") {
    TemporaryDatabase database;
    const SignalSample sample{"temperature", 42.5, observed_at, observed_at, "Good"};
    {
        LocalStorage storage(database.path());
        storage.save_check(critical_result());
        storage.save_log_state({"log", 123, 456, 789, observed_at});
        storage.save_file_state({"archive", 4096, observed_at, observed_at - 5s});
        storage.save_signal_history(sample);
    }
    {
        LocalStorage storage(database.path());
        REQUIRE(storage.load_checks().size() == 1);
        REQUIRE(storage.load_log_state("log")->offset == 123);
        REQUIRE(storage.load_log_state("log")->file_id == 456);
        REQUIRE(storage.load_file_state("archive")->size == 4096);
        REQUIRE(storage.load_signal_history().front().value == 42.5);
    }
}

TEST_CASE("incident restore does not emit a duplicate open event") {
    TemporaryDatabase database;
    {
        LocalStorage storage(database.path());
        IncidentManager manager("site", "host");
        const auto events = manager.process(critical_result(), observed_at);
        REQUIRE(events.size() == 1);
        storage.save_incident(events.front().incident);
    }
    {
        LocalStorage storage(database.path());
        IncidentManager manager("site", "host", {}, storage.load_incidents());
        REQUIRE(manager.active_incidents().size() == 1);
        REQUIRE(manager.process(critical_result(), observed_at + 1s).empty());
    }
}

TEST_CASE("event queue and sequence number persist") {
    TemporaryDatabase database;
    std::uint64_t sequence{};
    {
        LocalStorage storage(database.path());
        sequence = storage.next_sequence_number();
        storage.enqueue_event({{"event", 1}}, 1);
        storage.enqueue_event({{"event", 2}}, 1);
        REQUIRE(storage.pending_event_count() == 2);
        REQUIRE(storage.oldest_pending_event_at().has_value());
    }
    {
        LocalStorage storage(database.path());
        REQUIRE(storage.next_sequence_number() > sequence);
        const auto events = storage.pending_events(10);
        REQUIRE(events.size() == 2);
        storage.mark_event_sent(events.front().first);
        REQUIRE(storage.pending_event_count() == 1);
    }
}

TEST_CASE("telemetry overflow removes oldest telemetry but never incidents") {
    TemporaryDatabase database;
    LocalStorage storage(database.path());
    const auto envelope = [](const std::string& kind, const int value) {
        return nlohmann::json{{"delivery_path", "/test"},
                              {"body",
                               {{"message_id", generate_uuid_v4()},
                                {"message_kind", kind},
                                {"sequence_number", value},
                                {"payload", {{"value", value}}}}}};
    };

    storage.enqueue_event(envelope("incidents", 1), 1);
    storage.enqueue_event(envelope("signal_samples", 2), 1);
    storage.enqueue_event(envelope("signal_samples", 3), 1);

    const auto messages = storage.pending_events(10);
    REQUIRE(messages.size() == 2);
    REQUIRE(messages[0].second.at("body").at("message_kind") == "incidents");
    REQUIRE(messages[1].second.at("body").at("sequence_number") == 3);
}
