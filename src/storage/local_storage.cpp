#include "scadaguard/local_storage.hpp"

#include <sqlite3.h>

#include <stdexcept>
#include <string_view>

namespace scadaguard {
namespace {

class Statement {
  public:
    Statement(sqlite3* database, const std::string_view sql) : database_(database) {
        if (sqlite3_prepare_v2(database, sql.data(), static_cast<int>(sql.size()), &value_,
                               nullptr) != SQLITE_OK) {
            throw std::runtime_error("SQLite prepare failed: " +
                                     std::string(sqlite3_errmsg(database)));
        }
    }

    ~Statement() {
        sqlite3_finalize(value_);
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    sqlite3_stmt* get() const noexcept {
        return value_;
    }

    void bind(const int index, const std::string& value) {
        check(sqlite3_bind_text(value_, index, value.c_str(), -1, SQLITE_TRANSIENT), "bind text");
    }

    void bind(const int index, const std::int64_t value) {
        check(sqlite3_bind_int64(value_, index, value), "bind integer");
    }

    void execute() {
        check(sqlite3_step(value_), "execute", SQLITE_DONE);
    }

  private:
    void check(const int result, const std::string_view operation,
               const int expected = SQLITE_OK) const {
        if (result != expected) {
            throw std::runtime_error("SQLite " + std::string(operation) +
                                     " failed: " + sqlite3_errmsg(database_));
        }
    }

    sqlite3* database_{};
    sqlite3_stmt* value_{};
};

class Transaction {
  public:
    explicit Transaction(sqlite3* database) : database_(database) {
        execute("BEGIN IMMEDIATE");
    }

    ~Transaction() {
        if (!committed_) {
            sqlite3_exec(database_, "ROLLBACK", nullptr, nullptr, nullptr);
        }
    }

    void commit() {
        execute("COMMIT");
        committed_ = true;
    }

  private:
    void execute(const char* sql) {
        if (sqlite3_exec(database_, sql, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("SQLite transaction failed: " +
                                     std::string(sqlite3_errmsg(database_)));
        }
    }

    sqlite3* database_{};
    bool committed_{false};
};

std::string column_text(sqlite3_stmt* statement, const int column) {
    const auto* value = sqlite3_column_text(statement, column);
    return value ? reinterpret_cast<const char*>(value) : std::string{};
}

} // namespace

LocalStorage::LocalStorage(const std::filesystem::path& path) {
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }

    const auto result = sqlite3_open_v2(
        path.string().c_str(), &db_,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (result != SQLITE_OK) {
        const std::string error = db_ ? sqlite3_errmsg(db_) : "open failed";
        if (db_) {
            sqlite3_close(db_);
        }
        db_ = nullptr;
        throw std::runtime_error("cannot open local state database: " + error);
    }

    sqlite3_extended_result_codes(db_, 1);
    sqlite3_busy_timeout(db_, 5'000);
    execute_unlocked("PRAGMA foreign_keys=ON");
    execute_unlocked("PRAGMA journal_mode=WAL");
    execute_unlocked("PRAGMA synchronous=NORMAL");
    migrate();
}

LocalStorage::~LocalStorage() {
    if (db_) {
        sqlite3_close(db_);
    }
}

void LocalStorage::execute_unlocked(const char* sql) const {
    char* error = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "unknown SQLite error";
        sqlite3_free(error);
        throw std::runtime_error("SQLite execute failed: " + message);
    }
}

int LocalStorage::schema_version_unlocked() const {
    Statement statement(db_, "SELECT version FROM schema_version LIMIT 1");
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::runtime_error("local database schema version is missing");
    }
    return sqlite3_column_int(statement.get(), 0);
}

int LocalStorage::schema_version() const {
    std::scoped_lock lock(mutex_);
    return schema_version_unlocked();
}

void LocalStorage::migrate() {
    execute_unlocked("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)");
    execute_unlocked("INSERT INTO schema_version(version) SELECT 1 WHERE NOT EXISTS "
                     "(SELECT 1 FROM schema_version)");
    execute_unlocked("CREATE TABLE IF NOT EXISTS check_state("
                     "check_id TEXT PRIMARY KEY,json TEXT NOT NULL,updated_at TEXT NOT NULL)");
    execute_unlocked("CREATE TABLE IF NOT EXISTS incidents("
                     "incident_id TEXT PRIMARY KEY,json TEXT NOT NULL,active INTEGER NOT NULL,"
                     "updated_at TEXT NOT NULL)");
    execute_unlocked(
        "CREATE TABLE IF NOT EXISTS event_queue("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,json TEXT NOT NULL,created_at TEXT NOT NULL,"
        "sent_at TEXT)");

    while (schema_version_unlocked() < 4) {
        switch (schema_version_unlocked()) {
        case 1:
            migrate_1_to_2();
            break;
        case 2:
            migrate_2_to_3();
            break;
        case 3:
            migrate_3_to_4();
            break;
        default:
            throw std::runtime_error("unsupported local database schema version");
        }
    }
    if (schema_version_unlocked() > 4) {
        throw std::runtime_error("local database was created by a newer ScadaGuard version");
    }
}

void LocalStorage::migrate_1_to_2() {
    Transaction transaction(db_);
    execute_unlocked("CREATE TABLE agent_state(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at "
                     "TEXT NOT NULL)");
    execute_unlocked("CREATE TABLE log_state("
                     "check_id TEXT PRIMARY KEY,offset INTEGER NOT NULL,file_id INTEGER NOT NULL,"
                     "volume_serial INTEGER NOT NULL,updated_at TEXT NOT NULL)");
    execute_unlocked("CREATE TABLE file_state("
                     "check_id TEXT PRIMARY KEY,size INTEGER NOT NULL,modified_at TEXT NOT NULL,"
                     "last_change_at TEXT NOT NULL)");
    execute_unlocked("CREATE TABLE signal_history("
                     "signal_id TEXT PRIMARY KEY,json TEXT NOT NULL,updated_at TEXT NOT NULL)");
    execute_unlocked("UPDATE schema_version SET version=2");
    transaction.commit();
}

void LocalStorage::migrate_2_to_3() {
    Transaction transaction(db_);
    execute_unlocked("CREATE TABLE outbound_queue("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT NOT NULL UNIQUE,"
                     "kind TEXT NOT NULL,sequence_number INTEGER NOT NULL,payload TEXT NOT NULL,"
                     "created_at TEXT NOT NULL,attempt_count INTEGER NOT NULL DEFAULT 0,"
                     "next_attempt_at TEXT)");
    execute_unlocked(
        "CREATE INDEX outbound_queue_delivery_idx ON outbound_queue(next_attempt_at,id)");
    execute_unlocked("INSERT OR IGNORE INTO outbound_queue("
                     "message_id,kind,sequence_number,payload,created_at) "
                     "SELECT 'legacy-' || id,'incidents',id,json,created_at FROM event_queue "
                     "WHERE sent_at IS NULL");
    execute_unlocked("UPDATE schema_version SET version=3");
    transaction.commit();
}

void LocalStorage::migrate_3_to_4() {
    Transaction transaction(db_);
    execute_unlocked("CREATE TABLE discovery_state("
                     "key TEXT PRIMARY KEY,json TEXT NOT NULL,updated_at TEXT NOT NULL)");
    execute_unlocked("UPDATE schema_version SET version=4");
    transaction.commit();
}

void LocalStorage::save_check(const CheckResult& result) {
    std::scoped_lock lock(mutex_);
    Statement statement(
        db_,
        "INSERT INTO check_state(check_id,json,updated_at)VALUES(?,?,?) "
        "ON CONFLICT(check_id)DO UPDATE SET json=excluded.json,updated_at=excluded.updated_at");
    statement.bind(1, result.check_id);
    statement.bind(2, nlohmann::json(result).dump());
    statement.bind(3, format_utc(result.observed_at));
    statement.execute();
}

std::vector<CheckResult> LocalStorage::load_checks() const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "SELECT json FROM check_state ORDER BY check_id");
    std::vector<CheckResult> results;
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        results.push_back(
            nlohmann::json::parse(column_text(statement.get(), 0)).get<CheckResult>());
    }
    return results;
}

void LocalStorage::save_incident(const Incident& incident) {
    std::scoped_lock lock(mutex_);
    Statement statement(db_,
                        "INSERT INTO incidents(incident_id,json,active,updated_at)VALUES(?,?,?,?) "
                        "ON CONFLICT(incident_id)DO UPDATE SET "
                        "json=excluded.json,active=excluded.active,updated_at=excluded.updated_at");
    statement.bind(1, incident.incident_id);
    statement.bind(2, nlohmann::json(incident).dump());
    statement.bind(3, static_cast<std::int64_t>(incident.active ? 1 : 0));
    statement.bind(4, format_utc(Clock::now()));
    statement.execute();
}

std::vector<Incident> LocalStorage::load_incidents() const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "SELECT json FROM incidents ORDER BY updated_at");
    std::vector<Incident> incidents;
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        incidents.push_back(nlohmann::json::parse(column_text(statement.get(), 0)).get<Incident>());
    }
    return incidents;
}

void LocalStorage::save_log_state(const LogCheckState& state) {
    std::scoped_lock lock(mutex_);
    Statement statement(
        db_,
        "INSERT INTO log_state(check_id,offset,file_id,volume_serial,updated_at)VALUES(?,?,?,?,?) "
        "ON CONFLICT(check_id)DO UPDATE SET offset=excluded.offset,file_id=excluded.file_id,"
        "volume_serial=excluded.volume_serial,updated_at=excluded.updated_at");
    statement.bind(1, state.check_id);
    statement.bind(2, static_cast<std::int64_t>(state.offset));
    statement.bind(3, static_cast<std::int64_t>(state.file_id));
    statement.bind(4, static_cast<std::int64_t>(state.volume_serial));
    statement.bind(5, format_utc(state.updated_at));
    statement.execute();
}

std::optional<LogCheckState> LocalStorage::load_log_state(const std::string& check_id) const {
    std::scoped_lock lock(mutex_);
    Statement statement(
        db_, "SELECT offset,file_id,volume_serial,updated_at FROM log_state WHERE check_id=?");
    statement.bind(1, check_id);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return LogCheckState{check_id,
                         static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0)),
                         static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1)),
                         static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 2)),
                         parse_utc(column_text(statement.get(), 3))};
}

void LocalStorage::save_file_state(const FileCheckState& state) {
    std::scoped_lock lock(mutex_);
    Statement statement(
        db_,
        "INSERT INTO file_state(check_id,size,modified_at,last_change_at)VALUES(?,?,?,?) "
        "ON CONFLICT(check_id)DO UPDATE SET size=excluded.size,modified_at=excluded.modified_at,"
        "last_change_at=excluded.last_change_at");
    statement.bind(1, state.check_id);
    statement.bind(2, static_cast<std::int64_t>(state.size));
    statement.bind(3, format_utc(state.modified_at));
    statement.bind(4, format_utc(state.last_change_at));
    statement.execute();
}

std::optional<FileCheckState> LocalStorage::load_file_state(const std::string& check_id) const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_,
                        "SELECT size,modified_at,last_change_at FROM file_state WHERE check_id=?");
    statement.bind(1, check_id);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return FileCheckState{
        check_id, static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0)),
        parse_utc(column_text(statement.get(), 1)), parse_utc(column_text(statement.get(), 2))};
}

void LocalStorage::save_signal_history(const SignalSample& sample) {
    std::scoped_lock lock(mutex_);
    Statement statement(
        db_,
        "INSERT INTO signal_history(signal_id,json,updated_at)VALUES(?,?,?) "
        "ON CONFLICT(signal_id)DO UPDATE SET json=excluded.json,updated_at=excluded.updated_at");
    statement.bind(1, sample.signal_id);
    statement.bind(2, nlohmann::json(sample).dump());
    statement.bind(3, format_utc(Clock::now()));
    statement.execute();
}

std::vector<SignalSample> LocalStorage::load_signal_history() const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "SELECT json FROM signal_history ORDER BY signal_id");
    std::vector<SignalSample> samples;
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        samples.push_back(
            nlohmann::json::parse(column_text(statement.get(), 0)).get<SignalSample>());
    }
    return samples;
}

std::string LocalStorage::start_new_boot() {
    std::scoped_lock lock(mutex_);
    const auto boot_id = generate_uuid_v4();
    Statement statement(
        db_, "INSERT INTO agent_state(key,value,updated_at)VALUES('boot_id',?,?) "
             "ON CONFLICT(key)DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at");
    statement.bind(1, boot_id);
    statement.bind(2, format_utc(Clock::now()));
    statement.execute();
    return boot_id;
}

std::uint64_t LocalStorage::next_sequence_number() {
    std::scoped_lock lock(mutex_);
    Transaction transaction(db_);
    execute_unlocked(
        "INSERT INTO "
        "agent_state(key,value,updated_at)VALUES('sequence_number','0','1970-01-01T00:00:00Z') "
        "ON CONFLICT(key)DO NOTHING");
    std::uint64_t sequence{};
    {
        Statement update(db_, "UPDATE agent_state SET value=CAST(value AS INTEGER)+1,updated_at=? "
                              "WHERE key='sequence_number' RETURNING CAST(value AS INTEGER)");
        update.bind(1, format_utc(Clock::now()));
        if (sqlite3_step(update.get()) != SQLITE_ROW) {
            throw std::runtime_error("failed to allocate outbound sequence number");
        }
        sequence = static_cast<std::uint64_t>(sqlite3_column_int64(update.get(), 0));
    }
    transaction.commit();
    return sequence;
}

void LocalStorage::enqueue_event(const nlohmann::json& event, const std::size_t max_size) {
    std::scoped_lock lock(mutex_);
    Transaction transaction(db_);
    execute_unlocked(
        "INSERT INTO "
        "agent_state(key,value,updated_at)VALUES('sequence_number','0','1970-01-01T00:00:00Z') "
        "ON CONFLICT(key)DO NOTHING");
    std::int64_t sequence{};
    {
        Statement sequence_statement(
            db_, "UPDATE agent_state SET value=CAST(value AS INTEGER)+1,updated_at=? "
                 "WHERE key='sequence_number' RETURNING CAST(value AS INTEGER)");
        sequence_statement.bind(1, format_utc(Clock::now()));
        if (sqlite3_step(sequence_statement.get()) != SQLITE_ROW) {
            throw std::runtime_error("failed to allocate event sequence number");
        }
        sequence = sqlite3_column_int64(sequence_statement.get(), 0);
    }

    const auto& message = event.contains("body") ? event.at("body") : event;
    const auto kind = message.value("message_kind", std::string("incidents"));
    const auto message_id = message.value("message_id", generate_uuid_v4());
    const auto persisted_sequence =
        message.value("sequence_number", static_cast<std::uint64_t>(sequence));

    if (kind != "incidents" && max_size > 0) {
        Statement trim(
            db_,
            "DELETE FROM outbound_queue WHERE id IN ("
            "SELECT id FROM outbound_queue WHERE kind NOT IN('incident','incidents') ORDER BY id "
            "LIMIT MAX(0,(SELECT COUNT(*) FROM outbound_queue "
            "WHERE kind NOT IN('incident','incidents'))-?+1))");
        trim.bind(1, static_cast<std::int64_t>(max_size));
        trim.execute();
    }

    Statement insert(db_, "INSERT OR IGNORE INTO "
                          "outbound_queue(message_id,kind,sequence_number,payload,created_at) "
                          "VALUES(?,?,?,?,?)");
    insert.bind(1, message_id);
    insert.bind(2, kind);
    insert.bind(3, static_cast<std::int64_t>(persisted_sequence));
    insert.bind(4, event.dump());
    insert.bind(5, format_utc(Clock::now()));
    insert.execute();
    transaction.commit();
}

std::vector<std::pair<std::int64_t, nlohmann::json>>
LocalStorage::pending_events(const std::size_t limit) const {
    std::scoped_lock lock(mutex_);
    Statement statement(
        db_, "SELECT id,payload FROM outbound_queue "
             "WHERE (next_attempt_at IS NULL OR next_attempt_at<=?) ORDER BY id LIMIT ?");
    statement.bind(1, format_utc(Clock::now()));
    statement.bind(2, static_cast<std::int64_t>(limit));
    std::vector<std::pair<std::int64_t, nlohmann::json>> events;
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        events.emplace_back(sqlite3_column_int64(statement.get(), 0),
                            nlohmann::json::parse(column_text(statement.get(), 1)));
    }
    return events;
}

void LocalStorage::mark_event_sent(const std::int64_t id) {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "DELETE FROM outbound_queue WHERE id=?");
    statement.bind(1, id);
    statement.execute();
}

void LocalStorage::mark_event_failed(const std::int64_t id,
                                     const std::chrono::seconds retry_delay) {
    std::scoped_lock lock(mutex_);
    Statement statement(
        db_,
        "UPDATE outbound_queue SET attempt_count=attempt_count+1,next_attempt_at=? WHERE id=?");
    statement.bind(1, format_utc(Clock::now() + retry_delay));
    statement.bind(2, id);
    statement.execute();
}

std::size_t LocalStorage::pending_event_count() const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "SELECT COUNT(*) FROM outbound_queue");
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::runtime_error("failed to count pending events");
    }
    return static_cast<std::size_t>(sqlite3_column_int64(statement.get(), 0));
}

std::optional<TimePoint> LocalStorage::oldest_pending_event_at() const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "SELECT created_at FROM outbound_queue ORDER BY id LIMIT 1");
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return parse_utc(column_text(statement.get(), 0));
}

void LocalStorage::save_discovery_report(const nlohmann::json& report) {
    std::scoped_lock lock(mutex_);
    Statement statement(
        db_, "INSERT INTO discovery_state(key,json,updated_at)VALUES('latest_report',?,?) "
             "ON CONFLICT(key)DO UPDATE SET json=excluded.json,updated_at=excluded.updated_at");
    statement.bind(1, report.dump());
    statement.bind(2, format_utc(Clock::now()));
    statement.execute();
}

std::optional<nlohmann::json> LocalStorage::load_discovery_report() const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "SELECT json FROM discovery_state WHERE key='latest_report'");
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return nlohmann::json::parse(column_text(statement.get(), 0));
}

void LocalStorage::save_working_central_configuration(const nlohmann::json& configuration) {
    std::scoped_lock lock(mutex_);
    Transaction transaction(db_);
    execute_unlocked(
        "INSERT INTO agent_state(key,value,updated_at) "
        "SELECT 'previous_central_configuration',value,updated_at FROM agent_state "
        "WHERE key='working_central_configuration' "
        "ON CONFLICT(key)DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at");
    Statement statement(
        db_, "INSERT INTO agent_state(key,value,updated_at)VALUES("
             "'working_central_configuration',?,?) ON CONFLICT(key)DO UPDATE SET "
             "value=excluded.value,updated_at=excluded.updated_at");
    statement.bind(1, configuration.dump());
    statement.bind(2, format_utc(Clock::now()));
    statement.execute();
    transaction.commit();
}

std::optional<nlohmann::json> LocalStorage::load_working_central_configuration() const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "SELECT value FROM agent_state "
                             "WHERE key='working_central_configuration'");
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return nlohmann::json::parse(column_text(statement.get(), 0));
}

std::optional<nlohmann::json> LocalStorage::load_previous_central_configuration() const {
    std::scoped_lock lock(mutex_);
    Statement statement(db_, "SELECT value FROM agent_state "
                             "WHERE key='previous_central_configuration'");
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return nlohmann::json::parse(column_text(statement.get(), 0));
}

} // namespace scadaguard
