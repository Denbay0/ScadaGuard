#pragma once

#include "scadaguard/model.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace scadaguard {

enum class DiscoveryConfidence { Unknown, Low, Medium, High, Confirmed };
enum class DiscoveryStatus {
    Detected,
    Confirmed,
    Configured,
    Monitoring,
    NotFound,
    Ambiguous,
    Unsupported,
    Error
};
enum class ArchiveCandidateType {
    ConfigurationDatabase,
    RuntimeDatabase,
    DataArchiveCandidate,
    EventsArchiveCandidate,
    UnknownDatabase
};

struct DiscoveryLimits {
    std::size_t maximum_directories{500};
    std::size_t maximum_files{10'000};
    std::size_t maximum_depth{4};
    std::chrono::milliseconds maximum_duration{std::chrono::seconds(30)};
    std::size_t maximum_inspected_bytes{64 * 1024};
};

struct DiscoveryHints {
    std::vector<std::string> keywords{"masterscada", "mpssoft", "мпс софт", "mplc",
                                      "masterscada4d"};
    std::vector<std::filesystem::path> additional_roots;
    std::vector<std::filesystem::path> relative_log_directories{"log", "logs"};
    DiscoveryLimits limits;
};

struct ProcessDiscoveryRecord {
    std::uint32_t pid{};
    std::uint32_t parent_pid{};
    std::string name;
    std::filesystem::path executable_path;
    std::string architecture;
    std::string version;
    std::string company;
    std::string product;
};

struct ServiceDiscoveryRecord {
    std::string name;
    std::string display_name;
    std::string state;
    std::string start_type;
    std::filesystem::path executable_path;
    std::string account;
    std::uint32_t pid{};
};

struct InstalledApplicationRecord {
    std::string display_name;
    std::string display_version;
    std::filesystem::path install_location;
    std::string uninstall_string;
    std::string publisher;
};

struct DirectoryEntryRecord {
    std::filesystem::path path;
    bool is_directory{};
    bool is_reparse_point{};
    std::uintmax_t size{};
    TimePoint last_write_time{};
};

struct SqliteObjectMetadata {
    std::string name;
    std::string type;
    std::vector<std::string> columns;
    struct Column {
        std::string name;
        std::string declared_type;
        bool not_null{};
        bool primary_key{};
    };
    struct Index {
        std::string name;
        bool unique{};
        std::vector<std::string> columns;
    };
    struct ForeignKey {
        std::string from_column;
        std::string target_table;
        std::string target_column;
    };
    std::vector<Column> column_metadata;
    std::vector<Index> indexes;
    std::vector<ForeignKey> foreign_keys;
    std::optional<std::uint64_t> bounded_row_count;
    bool row_count_limit_reached{};
    std::vector<nlohmann::json> recent_samples;
};

struct ArchiveSchemaRoles {
    std::optional<std::string> timestamp;
    std::optional<std::string> signal_id;
    std::optional<std::string> value;
    std::optional<std::string> quality;
};

struct ArchiveSchemaCandidate {
    std::string table;
    DiscoveryConfidence confidence{DiscoveryConfidence::Unknown};
    ArchiveSchemaRoles roles;
    std::vector<std::string> evidence;
    bool needs_confirmation{true};
    std::optional<std::string> minimum_timestamp;
    std::optional<std::string> maximum_timestamp;
};

struct SqliteInspection {
    bool read_only_opened{};
    bool wal_exists{};
    bool shm_exists{};
    std::vector<SqliteObjectMetadata> objects;
    std::vector<ArchiveSchemaCandidate> schema_candidates;
    std::string error;
};

class ArchiveSchemaAnalyzer {
  public:
    static std::vector<ArchiveSchemaCandidate> analyze(const SqliteInspection& inspection);
};

class IDiscoveryEnvironment {
  public:
    virtual ~IDiscoveryEnvironment() = default;
    virtual std::vector<ProcessDiscoveryRecord> processes(std::stop_token stop) const = 0;
    virtual std::vector<ServiceDiscoveryRecord> services(std::stop_token stop) const = 0;
    virtual std::vector<InstalledApplicationRecord>
    installed_applications(std::stop_token stop) const = 0;
    virtual std::vector<std::filesystem::path> standard_roots() const = 0;
    virtual std::vector<DirectoryEntryRecord>
    list_directory(const std::filesystem::path& path) const = 0;
    virtual std::optional<std::string> read_prefix(const std::filesystem::path& path,
                                                   std::size_t maximum_bytes) const = 0;
    virtual std::optional<std::string> read_tail(const std::filesystem::path& path,
                                                 std::size_t maximum_bytes) const = 0;
    virtual SqliteInspection inspect_sqlite(const std::filesystem::path& path) const = 0;
};

struct DiscoveredComponent {
    std::string id;
    std::string type;
    std::filesystem::path path;
    DiscoveryConfidence confidence{DiscoveryConfidence::Unknown};
    std::vector<std::string> evidence;
    bool selected{};
    int score{};
    nlohmann::json details = nlohmann::json::object();
};

struct DiscoveredLogSource {
    std::filesystem::path path;
    std::string type{"text_log"};
    TimePoint last_write_time{};
    std::uintmax_t size{};
    DiscoveryConfidence confidence{DiscoveryConfidence::Unknown};
    std::vector<std::string> evidence;
    bool selected{};
    int score{};
};

struct ArchiveCandidate {
    std::filesystem::path path;
    ArchiveCandidateType type{ArchiveCandidateType::UnknownDatabase};
    TimePoint last_write_time{};
    std::uintmax_t size{};
    bool sqlite_header_valid{};
    bool read_only_opened{};
    bool wal_exists{};
    bool shm_exists{};
    std::vector<SqliteObjectMetadata> objects;
    std::vector<ArchiveSchemaCandidate> schema_candidates;
    DiscoveryConfidence confidence{DiscoveryConfidence::Unknown};
    std::vector<std::string> evidence;
    bool selected{};
    bool needs_confirmation{true};
    int score{};
    std::string error;
};

struct DiscoverySelection {
    std::optional<std::filesystem::path> confirmed_archive;
    std::optional<std::filesystem::path> configured_archive;
    std::vector<std::filesystem::path> confirmed_logs;
};

struct DiscoveryReport {
    std::string scan_id;
    TimePoint scanned_at{};
    DiscoveryStatus status{DiscoveryStatus::NotFound};
    DiscoveryConfidence confidence{DiscoveryConfidence::Unknown};
    bool masterscada_detected{};
    std::string version;
    std::vector<DiscoveredComponent> components;
    std::vector<ArchiveCandidate> archive_candidates;
    std::vector<DiscoveredLogSource> log_candidates;
    std::vector<std::string> opcua_candidates;
    std::vector<std::string> warnings;
    std::size_t scanned_directories{};
    std::size_t scanned_files{};
    bool truncated{};
};

class MasterScadaDiscovery {
  public:
    MasterScadaDiscovery(const IDiscoveryEnvironment& environment, DiscoveryHints hints = {});
    DiscoveryReport scan(const DiscoverySelection& selection = {}, std::stop_token stop = {}) const;

    static bool has_sqlite_header(std::string_view prefix);
    static DiscoveryConfidence confidence_from_score(int score);

  private:
    const IDiscoveryEnvironment& environment_;
    DiscoveryHints hints_;
};

std::string to_string(DiscoveryConfidence value);
std::string to_string(DiscoveryStatus value);
std::string to_string(ArchiveCandidateType value);
void to_json(nlohmann::json& json, const SqliteObjectMetadata& value);
void to_json(nlohmann::json& json, const SqliteObjectMetadata::Column& value);
void to_json(nlohmann::json& json, const SqliteObjectMetadata::Index& value);
void to_json(nlohmann::json& json, const SqliteObjectMetadata::ForeignKey& value);
void to_json(nlohmann::json& json, const ArchiveSchemaRoles& value);
void to_json(nlohmann::json& json, const ArchiveSchemaCandidate& value);
void to_json(nlohmann::json& json, const DiscoveredComponent& value);
void to_json(nlohmann::json& json, const DiscoveredLogSource& value);
void to_json(nlohmann::json& json, const ArchiveCandidate& value);
void to_json(nlohmann::json& json, const DiscoveryReport& value);

} // namespace scadaguard
