#include "scadaguard/discovery.hpp"

#include <algorithm>
#include <cctype>
#include <deque>
#include <map>
#include <ranges>
#include <set>
#include <sstream>

namespace scadaguard {
namespace {

std::string lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

bool contains(const std::string_view value, const std::string_view fragment) {
    return value.find(fragment) != std::string_view::npos;
}

bool contains_keyword(const std::string& value, const DiscoveryHints& hints) {
    const auto candidate = lower(value);
    return std::ranges::any_of(
        hints.keywords, [&](const auto& keyword) { return contains(candidate, lower(keyword)); });
}

std::string path_key(const std::filesystem::path& value) {
    return lower(value.lexically_normal().string());
}

bool same_path(const std::filesystem::path& left, const std::filesystem::path& right) {
    return path_key(left) == path_key(right);
}

bool restricted_root(const std::filesystem::path& value) {
    const auto normalized = lower(value.lexically_normal().string());
    if (normalized.starts_with("\\\\")) {
        return true;
    }
    const auto root = lower(value.root_path().string());
    if (!root.empty() && normalized == root) {
        return true;
    }
    return normalized == "c:\\windows" || normalized.starts_with("c:\\windows\\") ||
           normalized == "c:\\users" || normalized.starts_with("c:\\users\\");
}

bool recently_changed(const TimePoint value, const TimePoint now) {
    return value != TimePoint{} && value <= now && now - value <= std::chrono::hours(24);
}

bool timestamp_like(const SqliteObjectMetadata& object) {
    return std::ranges::any_of(object.columns, [](const auto& column) {
        const auto value = lower(column);
        return contains(value, "time") || contains(value, "date") || contains(value, "stamp");
    });
}

ArchiveCandidateType classify_database(const std::filesystem::path& path) {
    const auto name = lower(path.filename().string());
    if (contains(name, "config") || contains(name, "setting")) {
        return ArchiveCandidateType::ConfigurationDatabase;
    }
    if (contains(name, "event") || contains(name, "journal") || contains(name, "alarm")) {
        return ArchiveCandidateType::EventsArchiveCandidate;
    }
    if (contains(name, "archive") || contains(name, "history") || contains(name, "trend") ||
        contains(name, "data")) {
        return ArchiveCandidateType::DataArchiveCandidate;
    }
    if (contains(name, "runtime") || contains(name, "rt")) {
        return ArchiveCandidateType::RuntimeDatabase;
    }
    return ArchiveCandidateType::UnknownDatabase;
}

bool looks_like_log(const std::filesystem::path& path, const DiscoveryHints& hints) {
    const auto extension = lower(path.extension().string());
    const auto filename = lower(path.filename().string());
    const auto parent = lower(path.parent_path().filename().string());
    const auto configured_log_directory =
        std::ranges::any_of(hints.relative_log_directories, [&](const auto& relative) {
            return !relative.empty() && lower(relative.filename().string()) == parent;
        });
    const auto inside_log_directory =
        contains(parent, "log") || contains(parent, "journal") || configured_log_directory;
    return extension == ".log" || contains(filename, ".log.") || extension == ".trace" ||
           (extension == ".txt" && inside_log_directory);
}

bool log_content_matches(const std::string& value) {
    const auto candidate = lower(value);
    for (const auto* marker :
         {"masterscada", "mplc", "guardant", "license", "loadandprepare", "mpssoft"}) {
        if (contains(candidate, marker)) {
            return true;
        }
    }
    return false;
}

void append_unique(std::vector<std::string>& values, std::string value) {
    if (std::ranges::find(values, value) == values.end()) {
        values.push_back(std::move(value));
    }
}

struct RootCandidate {
    std::filesystem::path path;
    int score{};
    std::vector<std::string> evidence;
};

void add_root(std::map<std::string, RootCandidate>& roots, const std::filesystem::path& path,
              const int score, const std::string& evidence) {
    if (path.empty()) {
        return;
    }
    auto& candidate = roots[path_key(path)];
    if (candidate.path.empty()) {
        candidate.path = path.lexically_normal();
    }
    candidate.score += score;
    append_unique(candidate.evidence, evidence);
}

DiscoveredComponent component(std::string id, std::string type, const std::filesystem::path& path,
                              const int score, std::vector<std::string> evidence,
                              nlohmann::json details = nlohmann::json::object()) {
    return {std::move(id),
            std::move(type),
            path,
            MasterScadaDiscovery::confidence_from_score(score),
            std::move(evidence),
            false,
            score,
            std::move(details)};
}

} // namespace

MasterScadaDiscovery::MasterScadaDiscovery(const IDiscoveryEnvironment& environment,
                                           DiscoveryHints hints)
    : environment_(environment), hints_(std::move(hints)) {}

bool MasterScadaDiscovery::has_sqlite_header(const std::string_view prefix) {
    constexpr std::string_view header("SQLite format 3\0", 16);
    return prefix.size() >= header.size() && prefix.substr(0, header.size()) == header;
}

DiscoveryConfidence MasterScadaDiscovery::confidence_from_score(const int score) {
    if (score >= 75) {
        return DiscoveryConfidence::High;
    }
    if (score >= 40) {
        return DiscoveryConfidence::Medium;
    }
    if (score > 0) {
        return DiscoveryConfidence::Low;
    }
    return DiscoveryConfidence::Unknown;
}

DiscoveryReport MasterScadaDiscovery::scan(const DiscoverySelection& selection,
                                           const std::stop_token stop) const {
    DiscoveryReport report;
    report.scan_id = generate_uuid_v4();
    report.scanned_at = Clock::now();
    const auto started = std::chrono::steady_clock::now();
    std::map<std::string, RootCandidate> roots;

    for (const auto& process : environment_.processes(stop)) {
        const auto description = process.name + " " + process.executable_path.string() + " " +
                                 process.company + " " + process.product;
        if (!contains_keyword(description, hints_)) {
            continue;
        }
        int score = 30;
        std::vector<std::string> evidence{"running process"};
        if (contains_keyword(process.company + " " + process.product, hints_)) {
            score += 50;
            evidence.push_back("executable company/product metadata");
        }
        report.components.push_back(component("process:" + std::to_string(process.pid), "process",
                                              process.executable_path, score, evidence,
                                              {{"pid", process.pid},
                                               {"parent_pid", process.parent_pid},
                                               {"name", process.name},
                                               {"architecture", process.architecture},
                                               {"version", process.version},
                                               {"company", process.company},
                                               {"product", process.product}}));
        add_root(roots, process.executable_path.parent_path(), score, "running process executable");
        if (report.version.empty() && !process.version.empty()) {
            report.version = process.version;
        }
    }

    for (const auto& service : environment_.services(stop)) {
        const auto description =
            service.name + " " + service.display_name + " " + service.executable_path.string();
        if (!contains_keyword(description, hints_)) {
            continue;
        }
        const int score = 45;
        report.components.push_back(component("service:" + service.name, "service",
                                              service.executable_path, score,
                                              {"Windows Service binary path"},
                                              {{"service_name", service.name},
                                               {"display_name", service.display_name},
                                               {"state", service.state},
                                               {"start_type", service.start_type},
                                               {"account", service.account},
                                               {"pid", service.pid}}));
        add_root(roots, service.executable_path.parent_path(), score,
                 "Windows Service binary path");
    }

    for (const auto& application : environment_.installed_applications(stop)) {
        const auto description = application.display_name + " " + application.publisher + " " +
                                 application.install_location.string();
        if (!contains_keyword(description, hints_)) {
            continue;
        }
        const int score = contains_keyword(application.publisher, hints_) ? 40 : 25;
        report.components.push_back(component("registry:" + application.display_name,
                                              "installed_application", application.install_location,
                                              score, {"Windows installed applications registry"},
                                              {{"display_name", application.display_name},
                                               {"display_version", application.display_version},
                                               {"publisher", application.publisher}}));
        add_root(roots, application.install_location, score, "registry InstallLocation");
        if (report.version.empty() && !application.display_version.empty()) {
            report.version = application.display_version;
        }
    }

    for (const auto& root : environment_.standard_roots()) {
        add_root(roots, root, 10, "known MPSSoft directory hint");
    }
    for (const auto& root : hints_.additional_roots) {
        add_root(roots, root, 20, "explicit additional discovery root");
    }
    if (selection.confirmed_archive) {
        add_root(roots, selection.confirmed_archive->parent_path(), 100,
                 "administrator confirmed archive location");
    } else if (selection.configured_archive) {
        add_root(roots, selection.configured_archive->parent_path(), 60,
                 "explicit local archive configuration");
    }

    std::deque<std::pair<std::filesystem::path, std::size_t>> pending;
    for (const auto& [_, root] : roots) {
        if (restricted_root(root.path)) {
            report.warnings.push_back("unsafe discovery root was rejected: " + root.path.string());
            continue;
        }
        pending.emplace_back(root.path, 0);
    }
    std::set<std::string> visited;
    std::set<std::string> discovered_files;

    while (!pending.empty() && !stop.stop_requested()) {
        if (std::chrono::steady_clock::now() - started >= hints_.limits.maximum_duration) {
            report.truncated = true;
            report.warnings.push_back("scan duration limit reached");
            break;
        }
        if (report.scanned_directories >= hints_.limits.maximum_directories) {
            report.truncated = true;
            report.warnings.push_back("directory limit reached");
            break;
        }
        auto [directory, depth] = std::move(pending.front());
        pending.pop_front();
        if (!visited.insert(path_key(directory)).second) {
            continue;
        }
        ++report.scanned_directories;

        std::vector<DirectoryEntryRecord> entries;
        try {
            entries = environment_.list_directory(directory);
        } catch (const std::exception& error) {
            report.warnings.push_back("cannot inspect " + directory.string() + ": " + error.what());
            continue;
        }
        if (std::chrono::steady_clock::now() - started >= hints_.limits.maximum_duration) {
            report.truncated = true;
            append_unique(report.warnings, "scan duration limit reached");
            break;
        }
        if (!entries.empty()) {
            const auto root_iterator = roots.find(path_key(directory));
            if (root_iterator != roots.end()) {
                auto score = root_iterator->second.score + 10;
                auto evidence = root_iterator->second.evidence;
                evidence.push_back("directory exists and is readable");
                report.components.push_back(component("runtime:" + path_key(directory),
                                                      "runtime_directory", directory, score,
                                                      std::move(evidence)));
            }
        }

        for (const auto& entry : entries) {
            if (stop.stop_requested()) {
                break;
            }
            if (entry.is_directory) {
                if (entry.is_reparse_point) {
                    append_unique(report.warnings, "reparse point skipped: " + entry.path.string());
                } else if (depth < hints_.limits.maximum_depth) {
                    pending.emplace_back(entry.path, depth + 1);
                }
                continue;
            }
            if (report.scanned_files >= hints_.limits.maximum_files) {
                report.truncated = true;
                append_unique(report.warnings, "file limit reached");
                break;
            }
            ++report.scanned_files;
            if (!discovered_files.insert(path_key(entry.path)).second) {
                continue;
            }

            if (looks_like_log(entry.path, hints_)) {
                int score = 25;
                std::vector<std::string> evidence{"log filename or extension",
                                                  "inside a bounded MasterSCADA candidate tree"};
                const auto chunk =
                    std::max<std::size_t>(1, hints_.limits.maximum_inspected_bytes / 2);
                const auto prefix = environment_.read_prefix(entry.path, chunk);
                const auto tail = environment_.read_tail(entry.path, chunk);
                if ((prefix && log_content_matches(*prefix)) ||
                    (tail && log_content_matches(*tail))) {
                    score += 35;
                    evidence.push_back("bounded content sample contains MasterSCADA markers");
                }
                if (recently_changed(entry.last_write_time, report.scanned_at)) {
                    score += 15;
                    evidence.push_back("file changed within 24 hours");
                }
                report.log_candidates.push_back(
                    {entry.path, "text_log", entry.last_write_time, entry.size,
                     confidence_from_score(score), std::move(evidence),
                     std::ranges::any_of(
                         selection.confirmed_logs,
                         [&](const auto& path) { return same_path(path, entry.path); }),
                     score});
            }

            const auto prefix = environment_.read_prefix(entry.path, 16);
            if (!prefix || !has_sqlite_header(*prefix)) {
                continue;
            }
            auto inspection = environment_.inspect_sqlite(entry.path);
            int score = 30;
            std::vector<std::string> evidence{"SQLite magic header"};
            if (inspection.read_only_opened) {
                score += 25;
                evidence.push_back("opened with SQLITE_OPEN_READONLY");
            }
            if (!inspection.objects.empty()) {
                score += 10;
                evidence.push_back("contains tables or views");
            }
            if (std::ranges::any_of(inspection.objects, timestamp_like)) {
                score += 15;
                evidence.push_back("timestamp-like column metadata");
            }
            if (inspection.wal_exists || inspection.shm_exists) {
                score += 10;
                evidence.push_back("WAL or SHM sidecar exists");
            }
            if (recently_changed(entry.last_write_time, report.scanned_at)) {
                score += 15;
                evidence.push_back("database changed within 24 hours");
            }
            if (entry.size >= 10 * 1024 * 1024) {
                score += 10;
                evidence.push_back("database size is consistent with accumulated data");
            }
            ArchiveCandidate candidate;
            candidate.path = entry.path;
            candidate.type = classify_database(entry.path);
            candidate.last_write_time = entry.last_write_time;
            candidate.size = entry.size;
            candidate.sqlite_header_valid = true;
            candidate.read_only_opened = inspection.read_only_opened;
            candidate.wal_exists = inspection.wal_exists;
            candidate.shm_exists = inspection.shm_exists;
            candidate.objects = std::move(inspection.objects);
            candidate.schema_candidates = std::move(inspection.schema_candidates);
            candidate.confidence = confidence_from_score(score);
            candidate.evidence = std::move(evidence);
            candidate.score = score;
            candidate.error = std::move(inspection.error);
            report.archive_candidates.push_back(std::move(candidate));
        }
    }

    std::ranges::sort(report.archive_candidates,
                      [](const auto& left, const auto& right) { return left.score > right.score; });
    std::ranges::sort(report.log_candidates,
                      [](const auto& left, const auto& right) { return left.score > right.score; });

    auto select_archive = [&](const std::filesystem::path& path, const bool confirmed) {
        const auto found = std::ranges::find_if(report.archive_candidates, [&](const auto& item) {
            return same_path(item.path, path);
        });
        if (found == report.archive_candidates.end()) {
            ArchiveCandidate missing;
            missing.path = path;
            missing.selected = true;
            missing.needs_confirmation = false;
            missing.confidence =
                confirmed ? DiscoveryConfidence::Confirmed : DiscoveryConfidence::High;
            missing.error = "configured archive path disappeared or is not readable";
            missing.evidence.push_back(confirmed ? "administrator confirmed configuration"
                                                 : "explicit local configuration");
            report.archive_candidates.insert(report.archive_candidates.begin(), std::move(missing));
            report.warnings.push_back("configured archive path disappeared: " + path.string());
            report.status = DiscoveryStatus::Error;
            return;
        }
        found->selected = true;
        found->needs_confirmation = false;
        if (confirmed) {
            found->confidence = DiscoveryConfidence::Confirmed;
            found->evidence.push_back("administrator confirmed configuration");
        } else {
            found->evidence.push_back("explicit local configuration");
        }
    };

    if (selection.confirmed_archive) {
        select_archive(*selection.confirmed_archive, true);
        if (report.status != DiscoveryStatus::Error) {
            report.status = DiscoveryStatus::Confirmed;
        }
    } else if (selection.configured_archive) {
        select_archive(*selection.configured_archive, false);
        if (report.status != DiscoveryStatus::Error) {
            report.status = DiscoveryStatus::Configured;
        }
    } else {
        const auto high_count =
            std::ranges::count_if(report.archive_candidates, [](const auto& item) {
                return item.confidence == DiscoveryConfidence::High;
            });
        if (high_count == 1) {
            auto found = std::ranges::find_if(report.archive_candidates, [](const auto& item) {
                return item.confidence == DiscoveryConfidence::High;
            });
            found->selected = true;
            found->needs_confirmation = true;
        } else if (high_count > 1) {
            report.status = DiscoveryStatus::Ambiguous;
            report.warnings.push_back(
                "multiple high-confidence archive candidates require confirmation");
        }
    }

    report.masterscada_detected = std::ranges::any_of(report.components, [](const auto& item) {
        return item.type == "process" || item.type == "service" ||
               (item.type == "installed_application" && item.score >= 40) ||
               (item.type == "runtime_directory" && item.score >= 40);
    });
    const auto best_component = std::ranges::max_element(
        report.components, {}, [](const auto& item) { return item.score; });
    report.confidence = best_component == report.components.end() ? DiscoveryConfidence::Unknown
                                                                  : best_component->confidence;
    if (report.status != DiscoveryStatus::Confirmed &&
        report.status != DiscoveryStatus::Configured &&
        report.status != DiscoveryStatus::Ambiguous && report.status != DiscoveryStatus::Error) {
        report.status =
            report.masterscada_detected ? DiscoveryStatus::Detected : DiscoveryStatus::NotFound;
    }
    return report;
}

std::string to_string(const DiscoveryConfidence value) {
    switch (value) {
    case DiscoveryConfidence::Unknown:
        return "unknown";
    case DiscoveryConfidence::Low:
        return "low";
    case DiscoveryConfidence::Medium:
        return "medium";
    case DiscoveryConfidence::High:
        return "high";
    case DiscoveryConfidence::Confirmed:
        return "confirmed";
    }
    return "unknown";
}

std::string to_string(const DiscoveryStatus value) {
    switch (value) {
    case DiscoveryStatus::Detected:
        return "detected";
    case DiscoveryStatus::Confirmed:
        return "confirmed";
    case DiscoveryStatus::Configured:
        return "configured";
    case DiscoveryStatus::Monitoring:
        return "monitoring";
    case DiscoveryStatus::NotFound:
        return "not_found";
    case DiscoveryStatus::Ambiguous:
        return "ambiguous";
    case DiscoveryStatus::Unsupported:
        return "unsupported";
    case DiscoveryStatus::Error:
        return "error";
    }
    return "error";
}

std::string to_string(const ArchiveCandidateType value) {
    switch (value) {
    case ArchiveCandidateType::ConfigurationDatabase:
        return "configuration_database";
    case ArchiveCandidateType::RuntimeDatabase:
        return "runtime_database";
    case ArchiveCandidateType::DataArchiveCandidate:
        return "data_archive_candidate";
    case ArchiveCandidateType::EventsArchiveCandidate:
        return "events_archive_candidate";
    case ArchiveCandidateType::UnknownDatabase:
        return "unknown_database";
    }
    return "unknown_database";
}

void to_json(nlohmann::json& json, const SqliteObjectMetadata& value) {
    json = {{"name", value.name},
            {"type", value.type},
            {"columns", value.column_metadata},
            {"indexes", value.indexes},
            {"foreign_keys", value.foreign_keys},
            {"bounded_row_count", value.bounded_row_count ? nlohmann::json(*value.bounded_row_count)
                                                          : nlohmann::json(nullptr)},
            {"row_count_limit_reached", value.row_count_limit_reached},
            {"recent_samples", value.recent_samples}};
}

void to_json(nlohmann::json& json, const SqliteObjectMetadata::Column& value) {
    json = {{"name", value.name},
            {"declared_type", value.declared_type},
            {"not_null", value.not_null},
            {"primary_key", value.primary_key}};
}

void to_json(nlohmann::json& json, const SqliteObjectMetadata::Index& value) {
    json = {{"name", value.name}, {"unique", value.unique}, {"columns", value.columns}};
}

void to_json(nlohmann::json& json, const SqliteObjectMetadata::ForeignKey& value) {
    json = {{"from_column", value.from_column},
            {"target_table", value.target_table},
            {"target_column", value.target_column}};
}

void to_json(nlohmann::json& json, const ArchiveSchemaRoles& value) {
    json = {
        {"timestamp", value.timestamp ? nlohmann::json(*value.timestamp) : nlohmann::json(nullptr)},
        {"signal_id", value.signal_id ? nlohmann::json(*value.signal_id) : nlohmann::json(nullptr)},
        {"value", value.value ? nlohmann::json(*value.value) : nlohmann::json(nullptr)},
        {"quality", value.quality ? nlohmann::json(*value.quality) : nlohmann::json(nullptr)}};
}

void to_json(nlohmann::json& json, const ArchiveSchemaCandidate& value) {
    json = {{"table", value.table},
            {"confidence", to_string(value.confidence)},
            {"roles", value.roles},
            {"evidence", value.evidence},
            {"needs_confirmation", value.needs_confirmation},
            {"minimum_timestamp", value.minimum_timestamp ? nlohmann::json(*value.minimum_timestamp)
                                                          : nlohmann::json(nullptr)},
            {"maximum_timestamp", value.maximum_timestamp ? nlohmann::json(*value.maximum_timestamp)
                                                          : nlohmann::json(nullptr)}};
}

void to_json(nlohmann::json& json, const DiscoveredComponent& value) {
    json = {{"id", value.id},
            {"type", value.type},
            {"path", value.path.string()},
            {"confidence", to_string(value.confidence)},
            {"score", value.score},
            {"evidence", value.evidence},
            {"selected", value.selected},
            {"details", value.details}};
}

void to_json(nlohmann::json& json, const DiscoveredLogSource& value) {
    json = {{"path", value.path.string()},
            {"type", value.type},
            {"last_write_time", format_utc(value.last_write_time)},
            {"size", value.size},
            {"confidence", to_string(value.confidence)},
            {"score", value.score},
            {"evidence", value.evidence},
            {"selected", value.selected}};
}

void to_json(nlohmann::json& json, const ArchiveCandidate& value) {
    json = {{"path", value.path.string()},
            {"type", to_string(value.type)},
            {"last_write_time", format_utc(value.last_write_time)},
            {"size", value.size},
            {"sqlite_header_valid", value.sqlite_header_valid},
            {"read_only_opened", value.read_only_opened},
            {"wal_exists", value.wal_exists},
            {"shm_exists", value.shm_exists},
            {"objects", value.objects},
            {"schema_candidates", value.schema_candidates},
            {"confidence", to_string(value.confidence)},
            {"score", value.score},
            {"evidence", value.evidence},
            {"selected", value.selected},
            {"needs_confirmation", value.needs_confirmation},
            {"error", value.error}};
}

void to_json(nlohmann::json& json, const DiscoveryReport& value) {
    json = {{"scan_id", value.scan_id},
            {"scanned_at", format_utc(value.scanned_at)},
            {"masterscada",
             {{"detected", value.masterscada_detected},
              {"status", to_string(value.status)},
              {"version", value.version},
              {"confidence", to_string(value.confidence)}}},
            {"components", value.components},
            {"archive_candidates", value.archive_candidates},
            {"log_candidates", value.log_candidates},
            {"opcua_candidates", value.opcua_candidates},
            {"warnings", value.warnings},
            {"scan_limits",
             {{"scanned_directories", value.scanned_directories},
              {"scanned_files", value.scanned_files},
              {"truncated", value.truncated}}}};
}

} // namespace scadaguard
