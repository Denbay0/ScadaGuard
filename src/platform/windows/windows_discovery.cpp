#include "scadaguard/windows_discovery.hpp"

#include <sqlite3.h>

#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace scadaguard {
namespace {

template <typename T, auto Close> class WindowsHandle {
  public:
    explicit WindowsHandle(T value = {}) : value_(value) {}
    ~WindowsHandle() {
        if (value_ && value_ != reinterpret_cast<T>(INVALID_HANDLE_VALUE)) {
            Close(value_);
        }
    }
    WindowsHandle(const WindowsHandle&) = delete;
    WindowsHandle& operator=(const WindowsHandle&) = delete;
    T get() const noexcept {
        return value_;
    }
    explicit operator bool() const noexcept {
        return value_ && value_ != reinterpret_cast<T>(INVALID_HANDLE_VALUE);
    }

  private:
    T value_{};
};

std::string utf8(const std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const auto size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                          nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(),
                        size, nullptr, nullptr);
    return result;
}

std::wstring environment_wide(const wchar_t* name) {
    const auto required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) {
        return {};
    }
    std::wstring value(required, L'\0');
    const auto written = GetEnvironmentVariableW(name, value.data(), required);
    if (written == 0 || written >= required) {
        return {};
    }
    value.resize(written);
    return value;
}

bool default_process_candidate(const std::wstring& value) {
    std::wstring lowered(value);
    std::ranges::transform(lowered, lowered.begin(),
                           [](const wchar_t character) { return std::towlower(character); });
    return lowered.find(L"masterscada") != std::wstring::npos ||
           lowered.find(L"mpssoft") != std::wstring::npos ||
           lowered.find(L"mplc") != std::wstring::npos;
}

std::wstring expand_environment(const std::wstring& value) {
    const auto required = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (required == 0) {
        return value;
    }
    std::wstring expanded(required, L'\0');
    const auto written = ExpandEnvironmentStringsW(value.c_str(), expanded.data(), required);
    if (written == 0 || written > required) {
        return value;
    }
    expanded.resize(written - 1);
    return expanded;
}

std::filesystem::path executable_from_command(std::wstring command) {
    command = expand_environment(command);
    if (command.empty()) {
        return {};
    }
    if (command.front() == L'"') {
        const auto closing = command.find(L'"', 1);
        return closing == std::wstring::npos
                   ? std::filesystem::path(command.substr(1))
                   : std::filesystem::path(command.substr(1, closing - 1));
    }
    const auto executable_end = command.find(L".exe");
    if (executable_end != std::wstring::npos) {
        return std::filesystem::path(command.substr(0, executable_end + 4));
    }
    const auto space = command.find(L' ');
    return std::filesystem::path(command.substr(0, space));
}

std::string query_version_string(const std::vector<std::byte>& buffer, const WORD language,
                                 const WORD code_page, const wchar_t* name) {
    std::wostringstream key;
    key << L"\\StringFileInfo\\" << std::hex << std::setw(4) << std::setfill(L'0') << language
        << std::setw(4) << code_page << L'\\' << name;
    wchar_t* value = nullptr;
    UINT size = 0;
    if (!VerQueryValueW(buffer.data(), key.str().c_str(), reinterpret_cast<void**>(&value),
                        &size) ||
        !value || size == 0) {
        return {};
    }
    return utf8(std::wstring_view(value, size - 1));
}

void read_file_metadata(const std::filesystem::path& path, ProcessDiscoveryRecord& record) {
    DWORD ignored = 0;
    const auto size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (size == 0) {
        return;
    }
    std::vector<std::byte> buffer(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buffer.data())) {
        return;
    }
    struct Translation {
        WORD language;
        WORD code_page;
    };
    Translation* translations = nullptr;
    UINT translation_size = 0;
    if (!VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation",
                        reinterpret_cast<void**>(&translations), &translation_size) ||
        translation_size < sizeof(Translation)) {
        return;
    }
    record.company = query_version_string(buffer, translations[0].language,
                                          translations[0].code_page, L"CompanyName");
    record.product = query_version_string(buffer, translations[0].language,
                                          translations[0].code_page, L"ProductName");
    record.version = query_version_string(buffer, translations[0].language,
                                          translations[0].code_page, L"ProductVersion");
}

std::string process_architecture(HANDLE process) {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!IsWow64Process2(process, &process_machine, &native_machine)) {
        return "unknown";
    }
    const auto machine =
        process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine : process_machine;
    switch (machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        return "x64";
    case IMAGE_FILE_MACHINE_I386:
        return "x86";
    case IMAGE_FILE_MACHINE_ARM64:
        return "arm64";
    default:
        return "unknown";
    }
}

std::string service_state(const DWORD value) {
    switch (value) {
    case SERVICE_RUNNING:
        return "running";
    case SERVICE_STOPPED:
        return "stopped";
    case SERVICE_PAUSED:
        return "paused";
    case SERVICE_START_PENDING:
        return "start_pending";
    case SERVICE_STOP_PENDING:
        return "stop_pending";
    default:
        return "other";
    }
}

std::string service_start_type(const DWORD value) {
    switch (value) {
    case SERVICE_AUTO_START:
        return "automatic";
    case SERVICE_DEMAND_START:
        return "manual";
    case SERVICE_DISABLED:
        return "disabled";
    case SERVICE_BOOT_START:
        return "boot";
    case SERVICE_SYSTEM_START:
        return "system";
    default:
        return "unknown";
    }
}

std::string registry_string(HKEY key, const wchar_t* name) {
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(wchar_t)) {
        return {};
    }
    std::wstring value(bytes / sizeof(wchar_t), L'\0');
    if (RegQueryValueExW(key, name, nullptr, nullptr, reinterpret_cast<BYTE*>(value.data()),
                         &bytes) != ERROR_SUCCESS) {
        return {};
    }
    while (!value.empty() && value.back() == L'\0') {
        value.pop_back();
    }
    return utf8(type == REG_EXPAND_SZ ? expand_environment(value) : value);
}

std::vector<InstalledApplicationRecord> registry_applications(const wchar_t* path,
                                                              const std::stop_token stop) {
    HKEY raw_root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &raw_root) != ERROR_SUCCESS) {
        return {};
    }
    WindowsHandle<HKEY, RegCloseKey> root(raw_root);
    std::vector<InstalledApplicationRecord> applications;
    DWORD index = 0;
    std::array<wchar_t, 512> name{};
    while (!stop.stop_requested()) {
        DWORD name_size = static_cast<DWORD>(name.size());
        const auto result = RegEnumKeyExW(root.get(), index++, name.data(), &name_size, nullptr,
                                          nullptr, nullptr, nullptr);
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (result != ERROR_SUCCESS) {
            continue;
        }
        HKEY raw_application = nullptr;
        if (RegOpenKeyExW(root.get(), std::wstring(name.data(), name_size).c_str(), 0, KEY_READ,
                          &raw_application) != ERROR_SUCCESS) {
            continue;
        }
        WindowsHandle<HKEY, RegCloseKey> application(raw_application);
        InstalledApplicationRecord record;
        record.display_name = registry_string(application.get(), L"DisplayName");
        record.display_version = registry_string(application.get(), L"DisplayVersion");
        record.install_location = registry_string(application.get(), L"InstallLocation");
        record.uninstall_string = registry_string(application.get(), L"UninstallString");
        record.publisher = registry_string(application.get(), L"Publisher");
        if (!record.display_name.empty()) {
            applications.push_back(std::move(record));
        }
    }
    return applications;
}

TimePoint system_time(const std::filesystem::file_time_type value) {
    return std::chrono::time_point_cast<Clock::duration>(
        value - std::filesystem::file_time_type::clock::now() + Clock::now());
}

std::optional<std::string> read_block(const std::filesystem::path& path,
                                      const std::size_t maximum_bytes, const bool tail) {
    if (maximum_bytes == 0) {
        return std::string{};
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    if (tail) {
        input.seekg(0, std::ios::end);
        const auto length = input.tellg();
        if (length > static_cast<std::streamoff>(maximum_bytes)) {
            input.seekg(length - static_cast<std::streamoff>(maximum_bytes));
        } else {
            input.seekg(0);
        }
    }
    std::string result(maximum_bytes, '\0');
    input.read(result.data(), static_cast<std::streamsize>(maximum_bytes));
    result.resize(static_cast<std::size_t>(input.gcount()));
    return result;
}

std::string sqlite_text(sqlite3_stmt* statement, const int column) {
    const auto* value = sqlite3_column_text(statement, column);
    return value ? reinterpret_cast<const char*>(value) : std::string{};
}

std::string quote_identifier(std::string value) {
    std::string quoted{"\""};
    for (const char character : value) {
        quoted += character;
        if (character == '"') {
            quoted += '"';
        }
    }
    quoted += '"';
    return quoted;
}

nlohmann::json sqlite_value(sqlite3_stmt* statement, const int column,
                            std::size_t& remaining_bytes) {
    const auto type = sqlite3_column_type(statement, column);
    if (type == SQLITE_NULL) {
        return nullptr;
    }
    if (type == SQLITE_INTEGER) {
        return sqlite3_column_int64(statement, column);
    }
    if (type == SQLITE_FLOAT) {
        return sqlite3_column_double(statement, column);
    }
    const auto byte_count =
        static_cast<std::size_t>(std::max(0, sqlite3_column_bytes(statement, column)));
    const auto retained = std::min({byte_count, remaining_bytes, std::size_t{512}});
    remaining_bytes -= retained;
    if (type == SQLITE_BLOB) {
        return "<blob " + std::to_string(byte_count) + " bytes>";
    }
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    return text ? std::string(text, retained) : std::string{};
}

struct SqliteDeadline {
    std::chrono::steady_clock::time_point expires_at;
};

int stop_expired_query(void* context) {
    const auto* deadline = static_cast<const SqliteDeadline*>(context);
    return std::chrono::steady_clock::now() >= deadline->expires_at ? 1 : 0;
}

std::optional<std::string> indexed_boundary(sqlite3* database, const std::string& table,
                                            const std::string& column, const char* direction) {
    const auto sql = "SELECT " + quote_identifier(column) + " FROM " + quote_identifier(table) +
                     " WHERE " + quote_identifier(column) + " IS NOT NULL ORDER BY " +
                     quote_identifier(column) + " " + direction + " LIMIT 1";
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(database, sql.c_str(), -1, &raw, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw, sqlite3_finalize);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return sqlite_text(statement.get(), 0);
}

} // namespace

std::vector<ProcessDiscoveryRecord>
WindowsDiscoveryEnvironment::processes(const std::stop_token stop) const {
    WindowsHandle<HANDLE, CloseHandle> snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                "cannot enumerate Windows processes");
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::vector<ProcessDiscoveryRecord> records;
    if (!Process32FirstW(snapshot.get(), &entry)) {
        return records;
    }
    do {
        if (stop.stop_requested()) {
            break;
        }
        ProcessDiscoveryRecord record;
        record.pid = entry.th32ProcessID;
        record.parent_pid = entry.th32ParentProcessID;
        record.name = utf8(entry.szExeFile);
        WindowsHandle<HANDLE, CloseHandle> process(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID));
        if (process) {
            std::wstring path(32'768, L'\0');
            DWORD path_size = static_cast<DWORD>(path.size());
            if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &path_size)) {
                path.resize(path_size);
                record.executable_path = path;
                if (default_process_candidate(entry.szExeFile) || default_process_candidate(path)) {
                    read_file_metadata(record.executable_path, record);
                }
            }
            record.architecture = process_architecture(process.get());
        }
        records.push_back(std::move(record));
    } while (Process32NextW(snapshot.get(), &entry));
    return records;
}

std::vector<ServiceDiscoveryRecord>
WindowsDiscoveryEnvironment::services(const std::stop_token stop) const {
    WindowsHandle<SC_HANDLE, CloseServiceHandle> manager(
        OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
    if (!manager) {
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                "cannot enumerate Windows services");
    }
    DWORD bytes_needed = 0;
    DWORD count = 0;
    DWORD resume = 0;
    EnumServicesStatusExW(manager.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &bytes_needed, &count, &resume, nullptr);
    if (GetLastError() != ERROR_MORE_DATA || bytes_needed == 0) {
        return {};
    }
    std::vector<std::byte> buffer(bytes_needed);
    resume = 0;
    if (!EnumServicesStatusExW(manager.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, reinterpret_cast<BYTE*>(buffer.data()),
                               bytes_needed, &bytes_needed, &count, &resume, nullptr)) {
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                "cannot read Windows service list");
    }
    const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    std::vector<ServiceDiscoveryRecord> records;
    for (DWORD index = 0; index < count && !stop.stop_requested(); ++index) {
        ServiceDiscoveryRecord record;
        record.name = utf8(entries[index].lpServiceName);
        record.display_name = utf8(entries[index].lpDisplayName);
        record.state = service_state(entries[index].ServiceStatusProcess.dwCurrentState);
        record.pid = entries[index].ServiceStatusProcess.dwProcessId;
        WindowsHandle<SC_HANDLE, CloseServiceHandle> service(
            OpenServiceW(manager.get(), entries[index].lpServiceName, SERVICE_QUERY_CONFIG));
        if (service) {
            DWORD config_size = 0;
            QueryServiceConfigW(service.get(), nullptr, 0, &config_size);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && config_size > 0) {
                std::vector<std::byte> config_buffer(config_size);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config_buffer.data());
                if (QueryServiceConfigW(service.get(), config, config_size, &config_size)) {
                    record.executable_path = executable_from_command(config->lpBinaryPathName);
                    record.start_type = service_start_type(config->dwStartType);
                    record.account = utf8(config->lpServiceStartName);
                }
            }
        }
        records.push_back(std::move(record));
    }
    return records;
}

std::vector<InstalledApplicationRecord>
WindowsDiscoveryEnvironment::installed_applications(const std::stop_token stop) const {
    auto records =
        registry_applications(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", stop);
    auto wow = registry_applications(
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", stop);
    records.insert(records.end(), std::make_move_iterator(wow.begin()),
                   std::make_move_iterator(wow.end()));
    return records;
}

std::vector<std::filesystem::path> WindowsDiscoveryEnvironment::standard_roots() const {
    std::vector<std::filesystem::path> roots;
    const auto append = [&](const wchar_t* variable) {
        const auto value = environment_wide(variable);
        if (!value.empty()) {
            roots.emplace_back(std::filesystem::path(value) / L"MPSSoft");
        }
    };
    append(L"ProgramData");
    append(L"ProgramFiles");
    append(L"ProgramFiles(x86)");
    const auto program_data = environment_wide(L"ProgramData");
    if (!program_data.empty()) {
        roots.emplace_back(std::filesystem::path(program_data) / L"MPSSoft" / L"MasterSCADA4D_RT");
    }
    return roots;
}

std::vector<DirectoryEntryRecord>
WindowsDiscoveryEnvironment::list_directory(const std::filesystem::path& path) const {
    std::error_code error;
    std::filesystem::directory_iterator iterator(
        path, std::filesystem::directory_options::skip_permission_denied, error);
    if (error) {
        if (error == std::errc::no_such_file_or_directory) {
            return {};
        }
        throw std::system_error(error, "cannot open directory");
    }
    std::vector<DirectoryEntryRecord> entries;
    const std::filesystem::directory_iterator end;
    while (iterator != end) {
        const auto entry = *iterator;
        DirectoryEntryRecord record;
        record.path = entry.path();
        const auto attributes = GetFileAttributesW(record.path.c_str());
        record.is_reparse_point =
            attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT);
        record.is_directory = entry.is_directory(error);
        error.clear();
        if (!record.is_directory) {
            record.size = entry.file_size(error);
            error.clear();
        }
        const auto write_time = entry.last_write_time(error);
        if (!error) {
            record.last_write_time = system_time(write_time);
        }
        error.clear();
        entries.push_back(std::move(record));
        iterator.increment(error);
        if (error) {
            error.clear();
        }
    }
    return entries;
}

std::optional<std::string>
WindowsDiscoveryEnvironment::read_prefix(const std::filesystem::path& path,
                                         const std::size_t maximum_bytes) const {
    return read_block(path, maximum_bytes, false);
}

std::optional<std::string>
WindowsDiscoveryEnvironment::read_tail(const std::filesystem::path& path,
                                       const std::size_t maximum_bytes) const {
    return read_block(path, maximum_bytes, true);
}

SqliteInspection
WindowsDiscoveryEnvironment::inspect_sqlite(const std::filesystem::path& path) const {
    constexpr std::size_t maximum_objects = 100;
    constexpr std::size_t maximum_columns = 100;
    constexpr std::size_t maximum_indexes = 50;
    constexpr std::size_t maximum_foreign_keys = 100;
    constexpr std::size_t maximum_sample_rows = 5;
    constexpr std::uint64_t maximum_count = 10'000;
    constexpr std::size_t maximum_sample_bytes = 64 * 1024;
    SqliteInspection inspection;
    inspection.wal_exists = std::filesystem::exists(path.string() + "-wal");
    inspection.shm_exists = std::filesystem::exists(path.string() + "-shm");
    sqlite3* raw_database = nullptr;
    const auto open_result = sqlite3_open_v2(path.string().c_str(), &raw_database,
                                             SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
    if (open_result != SQLITE_OK) {
        inspection.error = raw_database ? sqlite3_errmsg(raw_database) : "SQLite open failed";
        if (raw_database) {
            sqlite3_close(raw_database);
        }
        return inspection;
    }
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(raw_database, sqlite3_close);
    inspection.read_only_opened = sqlite3_db_readonly(database.get(), "main") == 1;
    if (!inspection.read_only_opened) {
        inspection.error = "SQLite connection did not verify as read-only";
        return inspection;
    }
    sqlite3_busy_timeout(database.get(), 250);
    SqliteDeadline deadline{std::chrono::steady_clock::now() + std::chrono::seconds(2)};
    sqlite3_progress_handler(database.get(), 1'000, stop_expired_query, &deadline);
    sqlite3_stmt* raw_objects = nullptr;
    constexpr auto object_sql = "SELECT name,type FROM sqlite_master WHERE type IN('table','view') "
                                "AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 100";
    if (sqlite3_prepare_v2(database.get(), object_sql, -1, &raw_objects, nullptr) != SQLITE_OK) {
        inspection.error = sqlite3_errmsg(database.get());
        return inspection;
    }
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> objects(raw_objects,
                                                                       sqlite3_finalize);
    std::size_t sample_bytes_remaining = maximum_sample_bytes;
    while (inspection.objects.size() < maximum_objects &&
           sqlite3_step(objects.get()) == SQLITE_ROW) {
        SqliteObjectMetadata object;
        object.name = sqlite_text(objects.get(), 0);
        object.type = sqlite_text(objects.get(), 1);
        const auto pragma = "PRAGMA table_info(" + quote_identifier(object.name) + ")";
        sqlite3_stmt* raw_columns = nullptr;
        if (sqlite3_prepare_v2(database.get(), pragma.c_str(), -1, &raw_columns, nullptr) ==
            SQLITE_OK) {
            std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> columns(raw_columns,
                                                                               sqlite3_finalize);
            while (object.column_metadata.size() < maximum_columns &&
                   sqlite3_step(columns.get()) == SQLITE_ROW) {
                SqliteObjectMetadata::Column column;
                column.name = sqlite_text(columns.get(), 1);
                column.declared_type = sqlite_text(columns.get(), 2);
                column.not_null = sqlite3_column_int(columns.get(), 3) != 0;
                column.primary_key = sqlite3_column_int(columns.get(), 5) != 0;
                object.columns.push_back(column.name);
                object.column_metadata.push_back(std::move(column));
            }
        }

        if (object.type == "table") {
            const auto index_pragma = "PRAGMA index_list(" + quote_identifier(object.name) + ")";
            sqlite3_stmt* raw_indexes = nullptr;
            if (sqlite3_prepare_v2(database.get(), index_pragma.c_str(), -1, &raw_indexes,
                                   nullptr) == SQLITE_OK) {
                std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> indexes(
                    raw_indexes, sqlite3_finalize);
                while (object.indexes.size() < maximum_indexes &&
                       sqlite3_step(indexes.get()) == SQLITE_ROW) {
                    SqliteObjectMetadata::Index index;
                    index.name = sqlite_text(indexes.get(), 1);
                    index.unique = sqlite3_column_int(indexes.get(), 2) != 0;
                    const auto detail_pragma =
                        "PRAGMA index_info(" + quote_identifier(index.name) + ")";
                    sqlite3_stmt* raw_details = nullptr;
                    if (sqlite3_prepare_v2(database.get(), detail_pragma.c_str(), -1, &raw_details,
                                           nullptr) == SQLITE_OK) {
                        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> details(
                            raw_details, sqlite3_finalize);
                        while (index.columns.size() < maximum_columns &&
                               sqlite3_step(details.get()) == SQLITE_ROW) {
                            index.columns.push_back(sqlite_text(details.get(), 2));
                        }
                    }
                    object.indexes.push_back(std::move(index));
                }
            }

            const auto foreign_key_pragma =
                "PRAGMA foreign_key_list(" + quote_identifier(object.name) + ")";
            sqlite3_stmt* raw_foreign_keys = nullptr;
            if (sqlite3_prepare_v2(database.get(), foreign_key_pragma.c_str(), -1,
                                   &raw_foreign_keys, nullptr) == SQLITE_OK) {
                std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> foreign_keys(
                    raw_foreign_keys, sqlite3_finalize);
                while (object.foreign_keys.size() < maximum_foreign_keys &&
                       sqlite3_step(foreign_keys.get()) == SQLITE_ROW) {
                    object.foreign_keys.push_back({sqlite_text(foreign_keys.get(), 3),
                                                   sqlite_text(foreign_keys.get(), 2),
                                                   sqlite_text(foreign_keys.get(), 4)});
                }
            }

            const auto count_sql = "SELECT count(*) FROM (SELECT 1 FROM " +
                                   quote_identifier(object.name) + " LIMIT " +
                                   std::to_string(maximum_count + 1) + ")";
            sqlite3_stmt* raw_count = nullptr;
            if (sqlite3_prepare_v2(database.get(), count_sql.c_str(), -1, &raw_count, nullptr) ==
                SQLITE_OK) {
                std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> count(raw_count,
                                                                                 sqlite3_finalize);
                if (sqlite3_step(count.get()) == SQLITE_ROW) {
                    const auto value =
                        static_cast<std::uint64_t>(sqlite3_column_int64(count.get(), 0));
                    object.row_count_limit_reached = value > maximum_count;
                    object.bounded_row_count = std::min(value, maximum_count);
                }
            }

            if (!object.column_metadata.empty() && sample_bytes_remaining > 0) {
                const auto sample_sql = "SELECT * FROM " + quote_identifier(object.name) +
                                        " LIMIT " + std::to_string(maximum_sample_rows);
                sqlite3_stmt* raw_samples = nullptr;
                if (sqlite3_prepare_v2(database.get(), sample_sql.c_str(), -1, &raw_samples,
                                       nullptr) == SQLITE_OK) {
                    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> samples(
                        raw_samples, sqlite3_finalize);
                    while (object.recent_samples.size() < maximum_sample_rows &&
                           sample_bytes_remaining > 0 &&
                           sqlite3_step(samples.get()) == SQLITE_ROW) {
                        nlohmann::json row = nlohmann::json::object();
                        const auto count = std::min(sqlite3_column_count(samples.get()),
                                                    static_cast<int>(maximum_columns));
                        for (int column = 0; column < count && sample_bytes_remaining > 0;
                             ++column) {
                            row[sqlite3_column_name(samples.get(), column)] =
                                sqlite_value(samples.get(), column, sample_bytes_remaining);
                        }
                        object.recent_samples.push_back(std::move(row));
                    }
                }
            }
        }
        inspection.objects.push_back(std::move(object));
    }
    inspection.schema_candidates = ArchiveSchemaAnalyzer::analyze(inspection);
    for (auto& candidate : inspection.schema_candidates) {
        if (!candidate.roles.timestamp) {
            continue;
        }
        const auto object = std::ranges::find_if(
            inspection.objects, [&](const auto& item) { return item.name == candidate.table; });
        if (object == inspection.objects.end() ||
            !std::ranges::any_of(object->indexes, [&](const auto& index) {
                return std::ranges::find(index.columns, *candidate.roles.timestamp) !=
                       index.columns.end();
            })) {
            candidate.evidence.push_back(
                "timestamp range skipped because no supporting index was found");
            continue;
        }
        candidate.minimum_timestamp =
            indexed_boundary(database.get(), candidate.table, *candidate.roles.timestamp, "ASC");
        candidate.maximum_timestamp =
            indexed_boundary(database.get(), candidate.table, *candidate.roles.timestamp, "DESC");
        if (candidate.minimum_timestamp || candidate.maximum_timestamp) {
            candidate.evidence.push_back("timestamp range read through a supporting index");
        }
    }
    if (sqlite3_errcode(database.get()) == SQLITE_INTERRUPT && inspection.error.empty()) {
        inspection.error = "SQLite inspection reached its two-second query deadline";
    }
    sqlite3_progress_handler(database.get(), 0, nullptr, nullptr);
    return inspection;
}

} // namespace scadaguard
