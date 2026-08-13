#include "scadaguard/data_sources.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <map>
#include <memory>
#include <regex>
#include <sqlite3.h>
#include <sstream>
#include <stdexcept>

namespace scadaguard {

std::vector<SignalSample> MockCurrentDataSource::read_current(std::stop_token stop) {
    return stop.stop_requested() ? std::vector<SignalSample>{} : samples_;
}
void MockCurrentDataSource::set_samples(std::vector<SignalSample> s) {
    samples_ = std::move(s);
}
std::vector<SignalSample> MockArchiveDataSource::read_archive(TimePoint from, TimePoint to,
                                                              std::stop_token stop) {
    std::vector<SignalSample> out;
    for (const auto& s : samples_)
        if (!stop.stop_requested() && s.source_timestamp >= from && s.source_timestamp <= to)
            out.push_back(s);
    return out;
}
CsvReplayDataSource::CsvReplayDataSource(std::filesystem::path path) : path_(std::move(path)) {}
std::vector<SignalSample> CsvReplayDataSource::read_all(std::stop_token stop) const {
    std::ifstream input(path_);
    if (!input)
        throw std::runtime_error("cannot open CSV replay file: " + path_.string());
    std::vector<SignalSample> out;
    std::string line;
    bool first = true;
    while (std::getline(input, line)) {
        if (stop.stop_requested())
            break;
        if (first) {
            first = false;
            if (line.starts_with("signal_id,"))
                continue;
        }
        std::istringstream row(line);
        std::array<std::string, 5> f;
        for (auto& v : f)
            if (!std::getline(row, v, ','))
                throw std::runtime_error("invalid CSV replay row");
        out.push_back({f[0], std::stod(f[1]), parse_utc(f[2]), parse_utc(f[3]), f[4]});
    }
    return out;
}
std::vector<SignalSample> CsvReplayDataSource::read_current(std::stop_token stop) {
    auto all = read_all(stop);
    std::map<std::string, SignalSample> latest;
    for (auto& s : all)
        if (!latest.contains(s.signal_id) ||
            s.source_timestamp > latest[s.signal_id].source_timestamp)
            latest[s.signal_id] = s;
    std::vector<SignalSample> out;
    for (auto& [_, v] : latest)
        out.push_back(std::move(v));
    return out;
}
std::vector<SignalSample> CsvReplayDataSource::read_archive(TimePoint from, TimePoint to,
                                                            std::stop_token stop) {
    auto all = read_all(stop);
    std::erase_if(
        all, [&](const auto& s) { return s.source_timestamp < from || s.source_timestamp > to; });
    return all;
}
std::vector<SignalSample> OpcUaCurrentDataSource::read_current(std::stop_token) {
    throw std::runtime_error("OPC UA data source is not configured");
}
SqliteArchiveDataSource::SqliteArchiveDataSource(SqliteArchiveOptions o) : options_(std::move(o)) {}
bool SqliteArchiveDataSource::valid_identifier(const std::string& v) {
    static const std::regex allowed("^[A-Za-z_][A-Za-z0-9_]*$");
    return std::regex_match(v, allowed);
}
namespace {
struct ArchiveQueryLimit {
    std::stop_token stop;
    std::chrono::steady_clock::time_point deadline;
};
int cancel_archive_query(void* context) {
    const auto* limit = static_cast<const ArchiveQueryLimit*>(context);
    return limit->stop.stop_requested() || std::chrono::steady_clock::now() >= limit->deadline ? 1
                                                                                               : 0;
}
} // namespace
std::vector<SignalSample> SqliteArchiveDataSource::read_archive(TimePoint from, TimePoint to,
                                                                std::stop_token stop) {
    if (!options_.enabled)
        throw std::runtime_error("SQLite archive data source is disabled");
    for (const auto* v : {&options_.table, &options_.signal_id_column, &options_.timestamp_column,
                          &options_.value_column})
        if (!valid_identifier(*v))
            throw std::runtime_error("SQLite archive schema identifiers are missing or invalid");
    if (!options_.quality_column.empty() && !valid_identifier(options_.quality_column))
        throw std::runtime_error("SQLite archive quality identifier is invalid");
    if (options_.maximum_batch_size == 0 || options_.maximum_batch_size > 10'000)
        throw std::runtime_error("SQLite archive batch limit is outside the safe range");
    sqlite3* raw = nullptr;
    if (sqlite3_open_v2(options_.database_path.string().c_str(), &raw,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr) != SQLITE_OK) {
        std::string e = raw ? sqlite3_errmsg(raw) : "open failed";
        if (raw)
            sqlite3_close(raw);
        throw std::runtime_error("cannot open archive read-only: " + e);
    }
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db(raw, sqlite3_close);
    if (sqlite3_db_readonly(db.get(), "main") != 1)
        throw std::runtime_error("SQLite archive connection did not verify as read-only");
    sqlite3_busy_timeout(db.get(), 250);
    ArchiveQueryLimit query_limit{stop, std::chrono::steady_clock::now() + std::chrono::seconds(2)};
    sqlite3_progress_handler(db.get(), 1'000, cancel_archive_query, &query_limit);
    const auto quality_expression =
        options_.quality_column.empty() ? "'Unknown'" : options_.quality_column;
    const auto sql = "SELECT " + options_.signal_id_column + "," + options_.value_column + "," +
                     options_.timestamp_column + "," + quality_expression + " FROM " +
                     options_.table + " WHERE " + options_.timestamp_column + ">=? AND " +
                     options_.timestamp_column + "<=? ORDER BY " + options_.timestamp_column +
                     " LIMIT ?";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db.get(), sql.c_str(), -1, &raw_stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("archive schema is unavailable: " +
                                 std::string(sqlite3_errmsg(db.get())));
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw_stmt, sqlite3_finalize);
    sqlite3_bind_text(stmt.get(), 1, format_utc(from).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, format_utc(to).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, static_cast<sqlite3_int64>(options_.maximum_batch_size));
    std::vector<SignalSample> out;
    std::size_t remaining_bytes = 1024 * 1024;
    while (!stop.stop_requested() && sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto text = [](sqlite3_stmt* s, int i) {
            const auto* p = sqlite3_column_text(s, i);
            return p ? reinterpret_cast<const char*>(p) : "";
        };
        const auto row_bytes =
            static_cast<std::size_t>(std::max(0, sqlite3_column_bytes(stmt.get(), 0))) +
            static_cast<std::size_t>(std::max(0, sqlite3_column_bytes(stmt.get(), 2))) +
            static_cast<std::size_t>(std::max(0, sqlite3_column_bytes(stmt.get(), 3)));
        if (row_bytes > remaining_bytes)
            break;
        remaining_bytes -= row_bytes;
        const auto timestamp = parse_utc(text(stmt.get(), 2));
        out.push_back({text(stmt.get(), 0), sqlite3_column_double(stmt.get(), 1), timestamp,
                       Clock::now(), text(stmt.get(), 3)});
    }
    sqlite3_progress_handler(db.get(), 0, nullptr, nullptr);
    return out;
}

} // namespace scadaguard
