#include "scadaguard/discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <map>
#include <stdexcept>
#include <thread>

using namespace scadaguard;
using namespace std::chrono_literals;

namespace {

class FakeDiscoveryEnvironment final : public IDiscoveryEnvironment {
  public:
    std::vector<ProcessDiscoveryRecord> process_records;
    std::vector<ServiceDiscoveryRecord> service_records;
    std::vector<InstalledApplicationRecord> application_records;
    std::vector<std::filesystem::path> roots;
    std::map<std::string, std::vector<DirectoryEntryRecord>> directories;
    std::map<std::string, std::string> prefixes;
    std::map<std::string, std::string> tails;
    std::map<std::string, SqliteInspection> sqlite;
    std::vector<std::string> denied;
    std::chrono::milliseconds directory_delay{};

    std::vector<ProcessDiscoveryRecord> processes(std::stop_token) const override {
        return process_records;
    }
    std::vector<ServiceDiscoveryRecord> services(std::stop_token) const override {
        return service_records;
    }
    std::vector<InstalledApplicationRecord> installed_applications(std::stop_token) const override {
        return application_records;
    }
    std::vector<std::filesystem::path> standard_roots() const override {
        return roots;
    }
    std::vector<DirectoryEntryRecord>
    list_directory(const std::filesystem::path& path) const override {
        if (directory_delay > 0ms) {
            std::this_thread::sleep_for(directory_delay);
        }
        if (std::ranges::find(denied, path.string()) != denied.end()) {
            throw std::runtime_error("permission denied");
        }
        const auto found = directories.find(path.string());
        return found == directories.end() ? std::vector<DirectoryEntryRecord>{} : found->second;
    }
    std::optional<std::string> read_prefix(const std::filesystem::path& path,
                                           std::size_t maximum) const override {
        const auto found = prefixes.find(path.string());
        if (found == prefixes.end()) {
            return std::nullopt;
        }
        return found->second.substr(0, maximum);
    }
    std::optional<std::string> read_tail(const std::filesystem::path& path,
                                         std::size_t maximum) const override {
        const auto found = tails.find(path.string());
        if (found == tails.end()) {
            return std::nullopt;
        }
        return found->second.substr(found->second.size() > maximum ? found->second.size() - maximum
                                                                   : 0);
    }
    SqliteInspection inspect_sqlite(const std::filesystem::path& path) const override {
        const auto found = sqlite.find(path.string());
        return found == sqlite.end() ? SqliteInspection{} : found->second;
    }
};

std::string sqlite_header() {
    return std::string("SQLite format 3\0", 16);
}

void add_archive(FakeDiscoveryEnvironment& environment, const std::filesystem::path& root,
                 const std::string& name, const std::uintmax_t size = 20 * 1024 * 1024) {
    const auto path = root / name;
    environment.directories[root.string()].push_back({path, false, false, size, Clock::now()});
    environment.prefixes[path.string()] = sqlite_header();
    environment.sqlite[path.string()] = {
        true, true, true, {{"samples", "table", {"signal_id", "timestamp", "value"}}}, {}};
}

FakeDiscoveryEnvironment base_environment() {
    FakeDiscoveryEnvironment environment;
    environment.process_records.push_back({42, 1, "MasterSCADA4D.exe",
                                           R"(C:\MPSSoft\RT\MasterSCADA4D.exe)", "x64", "4.0",
                                           "MPSSoft", "MasterSCADA 4D"});
    environment.directories[R"(C:\MPSSoft\RT)"] = {};
    return environment;
}

} // namespace

TEST_CASE("SQLite discovery requires the binary magic header") {
    REQUIRE(MasterScadaDiscovery::has_sqlite_header(sqlite_header()));
    REQUIRE_FALSE(MasterScadaDiscovery::has_sqlite_header("not a sqlite database"));
    REQUIRE_FALSE(MasterScadaDiscovery::has_sqlite_header("SQLite format 3"));
}

TEST_CASE("process metadata produces high-confidence MasterSCADA evidence") {
    auto environment = base_environment();
    const auto report = MasterScadaDiscovery(environment).scan();
    REQUIRE(report.masterscada_detected);
    REQUIRE(report.confidence == DiscoveryConfidence::High);
    REQUIRE(report.version == "4.0");
}

TEST_CASE("service and registry records contribute independent discovery roots") {
    FakeDiscoveryEnvironment environment;
    environment.service_records.push_back({"mps-runtime", "MPSSoft Runtime", "running", "automatic",
                                           R"(D:\MPS\runtime.exe)", "LocalSystem", 100});
    environment.application_records.push_back(
        {"MasterSCADA", "4.2", R"(D:\MPS)", "uninstall.exe", "MPSSoft"});
    environment.directories[R"(D:\MPS)"] = {};
    const auto report = MasterScadaDiscovery(environment).scan();
    REQUIRE(report.masterscada_detected);
    REQUIRE(std::ranges::count_if(report.components,
                                  [](const auto& item) { return item.type == "service"; }) == 1);
    REQUIRE(std::ranges::count_if(report.components, [](const auto& item) {
                return item.type == "installed_application";
            }) == 1);
}

TEST_CASE("known directories are candidates but do not prove MasterSCADA alone") {
    FakeDiscoveryEnvironment environment;
    environment.roots.push_back(R"(C:\ProgramData\MPSSoft)");
    environment.directories[R"(C:\ProgramData\MPSSoft)"].push_back(
        {R"(C:\ProgramData\MPSSoft\readme.txt)", false, false, 10, Clock::now()});
    const auto report = MasterScadaDiscovery(environment).scan();
    REQUIRE_FALSE(report.masterscada_detected);
    REQUIRE(std::ranges::any_of(report.components,
                                [](const auto& item) { return item.type == "runtime_directory"; }));
}

TEST_CASE("multiple strong archive candidates stay ambiguous") {
    auto environment = base_environment();
    add_archive(environment, R"(C:\MPSSoft\RT)", "archive-a.bin");
    add_archive(environment, R"(C:\MPSSoft\RT)", "archive-b.db");
    const auto report = MasterScadaDiscovery(environment).scan();
    REQUIRE(report.archive_candidates.size() == 2);
    REQUIRE(report.status == DiscoveryStatus::Ambiguous);
    REQUIRE_FALSE(std::ranges::any_of(report.archive_candidates,
                                      [](const auto& item) { return item.selected; }));
}

TEST_CASE("administrator confirmed archive has priority over scoring") {
    auto environment = base_environment();
    add_archive(environment, R"(C:\MPSSoft\RT)", "archive-a.db");
    add_archive(environment, R"(C:\MPSSoft\RT)", "archive-b.db");
    const auto selected = std::filesystem::path(R"(C:\MPSSoft\RT\archive-b.db)");
    const auto report = MasterScadaDiscovery(environment).scan({selected, std::nullopt, {}});
    const auto chosen = std::ranges::find_if(report.archive_candidates,
                                             [](const auto& item) { return item.selected; });
    REQUIRE(chosen != report.archive_candidates.end());
    REQUIRE(chosen->path == selected);
    REQUIRE(chosen->confidence == DiscoveryConfidence::Confirmed);
    REQUIRE(report.status == DiscoveryStatus::Confirmed);
}

TEST_CASE("explicit local archive overrides automatic recommendation") {
    auto environment = base_environment();
    add_archive(environment, R"(C:\MPSSoft\RT)", "archive-a.db");
    add_archive(environment, R"(C:\MPSSoft\RT)", "archive-b.db", 1);
    const auto selected = std::filesystem::path(R"(C:\MPSSoft\RT\archive-b.db)");
    const auto report = MasterScadaDiscovery(environment).scan({std::nullopt, selected, {}});
    REQUIRE(report.status == DiscoveryStatus::Configured);
    REQUIRE(std::ranges::any_of(report.archive_candidates, [&](const auto& item) {
        return item.selected && item.path == selected;
    }));
}

TEST_CASE("disappeared confirmed archive is an error and is never silently switched") {
    auto environment = base_environment();
    add_archive(environment, R"(C:\MPSSoft\RT)", "other.db");
    const auto missing = std::filesystem::path(R"(C:\MPSSoft\RT\confirmed.db)");
    const auto report = MasterScadaDiscovery(environment).scan({missing, std::nullopt, {}});
    REQUIRE(report.status == DiscoveryStatus::Error);
    REQUIRE(report.archive_candidates.front().path == missing);
    REQUIRE(report.archive_candidates.front().selected);
    REQUIRE_FALSE(report.archive_candidates.front().sqlite_header_valid);
}

TEST_CASE("log discovery samples bounded content and handles rotated files") {
    auto environment = base_environment();
    for (const auto* name : {"runtime.log", "runtime.log.1"}) {
        const auto path = std::filesystem::path(R"(C:\MPSSoft\RT)") / name;
        environment.directories[R"(C:\MPSSoft\RT)"].push_back(
            {path, false, false, 2'000'000, Clock::now()});
        environment.prefixes[path.string()] = "MasterSCADA RT started";
        environment.tails[path.string()] = "Guardant license check";
    }
    const auto report = MasterScadaDiscovery(environment).scan();
    REQUIRE(report.log_candidates.size() == 2);
    REQUIRE(report.log_candidates.front().confidence == DiscoveryConfidence::High);
}

TEST_CASE("license text assets outside log directories are not log candidates") {
    auto environment = base_environment();
    const auto path = std::filesystem::path(R"(C:\MPSSoft\RT)") / "bundle.js.LICENSE.txt";
    environment.directories[R"(C:\MPSSoft\RT)"].push_back({path, false, false, 100, Clock::now()});
    environment.prefixes[path.string()] = "MasterSCADA license notices";
    const auto report = MasterScadaDiscovery(environment).scan();
    REQUIRE(report.log_candidates.empty());
}

TEST_CASE("protocol definition text assets are not log candidates by name alone") {
    auto environment = base_environment();
    const auto path = std::filesystem::path(R"(C:\MPSSoft\RT)") / "NOTIFICATION-LOG-MIB.txt";
    environment.directories[R"(C:\MPSSoft\RT)"].push_back({path, false, false, 100, Clock::now()});
    environment.prefixes[path.string()] = "protocol definition";
    const auto report = MasterScadaDiscovery(environment).scan();
    REQUIRE(report.log_candidates.empty());
}

TEST_CASE("configured relative log directory extends text log discovery") {
    auto environment = base_environment();
    environment.directories[R"(C:\MPSSoft\RT)"].push_back(
        {R"(C:\MPSSoft\RT\telemetry)", true, false, 0, Clock::now()});
    const auto path = std::filesystem::path(R"(C:\MPSSoft\RT\telemetry)") / "runtime.txt";
    environment.directories[R"(C:\MPSSoft\RT\telemetry)"].push_back(
        {path, false, false, 100, Clock::now()});
    environment.prefixes[path.string()] = "MasterSCADA RT started";
    DiscoveryHints hints;
    hints.relative_log_directories = {"telemetry"};
    const auto report = MasterScadaDiscovery(environment, hints).scan();
    REQUIRE(report.log_candidates.size() == 1);
}

TEST_CASE("scan limits protect against large directories") {
    auto environment = base_environment();
    for (int index = 0; index < 20; ++index) {
        environment.directories[R"(C:\MPSSoft\RT)"].push_back(
            {std::filesystem::path(R"(C:\MPSSoft\RT)") / ("file-" + std::to_string(index)), false,
             false, 1, Clock::now()});
    }
    DiscoveryHints hints;
    hints.limits.maximum_files = 3;
    const auto report = MasterScadaDiscovery(environment, hints).scan();
    REQUIRE(report.scanned_files == 3);
    REQUIRE(report.truncated);
}

TEST_CASE("depth limit and reparse protection prevent directory loops") {
    auto environment = base_environment();
    environment.directories[R"(C:\MPSSoft\RT)"].push_back(
        {R"(C:\MPSSoft\RT\junction)", true, true, 0, Clock::now()});
    environment.directories[R"(C:\MPSSoft\RT)"].push_back(
        {R"(C:\MPSSoft\RT\child)", true, false, 0, Clock::now()});
    environment.directories[R"(C:\MPSSoft\RT\child)"].push_back(
        {R"(C:\MPSSoft\RT\child\deep)", true, false, 0, Clock::now()});
    DiscoveryHints hints;
    hints.limits.maximum_depth = 1;
    const auto report = MasterScadaDiscovery(environment, hints).scan();
    REQUIRE(report.scanned_directories == 2);
    REQUIRE(std::ranges::any_of(report.warnings, [](const auto& warning) {
        return warning.find("reparse point skipped") != std::string::npos;
    }));
}

TEST_CASE("permission errors are reported without aborting discovery") {
    auto environment = base_environment();
    environment.denied.push_back(R"(C:\MPSSoft\RT)");
    const auto report = MasterScadaDiscovery(environment).scan();
    REQUIRE(std::ranges::any_of(report.warnings, [](const auto& warning) {
        return warning.find("permission denied") != std::string::npos;
    }));
}

TEST_CASE("scan timeout is enforced") {
    auto environment = base_environment();
    environment.directory_delay = 5ms;
    DiscoveryHints hints;
    hints.limits.maximum_duration = 1ms;
    const auto report = MasterScadaDiscovery(environment, hints).scan();
    REQUIRE(report.truncated);
    REQUIRE(std::ranges::any_of(report.warnings, [](const auto& warning) {
        return warning.find("duration limit") != std::string::npos;
    }));
}

TEST_CASE("discovery report JSON distinguishes detection from confirmation") {
    auto environment = base_environment();
    const auto report = MasterScadaDiscovery(environment).scan();
    const nlohmann::json json = report;
    REQUIRE(json.at("masterscada").at("status") == "detected");
    REQUIRE(json.at("masterscada").at("confidence") == "high");
    REQUIRE(json.at("scan_limits").at("truncated") == false);
}

TEST_CASE("archive schema analyzer infers roles without assuming a vendor table name") {
    SqliteObjectMetadata object;
    object.name = "history_2026";
    object.type = "table";
    object.column_metadata = {{"recorded_at", "INTEGER", true, false},
                              {"item_key", "TEXT", true, false},
                              {"measurement", "REAL", false, false},
                              {"quality_state", "INTEGER", false, false}};
    object.columns = {"recorded_at", "item_key", "measurement", "quality_state"};
    object.indexes = {{"history_time_item", false, {"recorded_at", "item_key"}}};
    object.bounded_row_count = 2;
    object.recent_samples = {
        {{"recorded_at", 1'786'000'000}, {"item_key", "alpha"}, {"measurement", 12.5}},
        {{"recorded_at", 1'786'000'001}, {"item_key", "alpha"}, {"measurement", 12.7}}};
    SqliteInspection inspection;
    inspection.read_only_opened = true;
    inspection.objects.push_back(std::move(object));

    const auto candidates = ArchiveSchemaAnalyzer::analyze(inspection);
    REQUIRE(candidates.size() == 1);
    REQUIRE(candidates.front().table == "history_2026");
    REQUIRE(candidates.front().roles.timestamp == "recorded_at");
    REQUIRE(candidates.front().roles.signal_id == "item_key");
    REQUIRE(candidates.front().roles.value == "measurement");
    REQUIRE(candidates.front().roles.quality == "quality_state");
    REQUIRE(candidates.front().confidence == DiscoveryConfidence::High);
    REQUIRE(candidates.front().needs_confirmation);
}

TEST_CASE("archive schema analyzer refuses to guess an opaque schema") {
    SqliteObjectMetadata object;
    object.name = "x";
    object.type = "table";
    object.column_metadata = {{"a", "BLOB", false, false}, {"b", "BLOB", false, false}};
    SqliteInspection inspection;
    inspection.objects.push_back(std::move(object));
    REQUIRE(ArchiveSchemaAnalyzer::analyze(inspection).empty());
}
