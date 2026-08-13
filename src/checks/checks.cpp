#include "scadaguard/checks.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace scadaguard {
namespace {
template <class T, auto Close> struct WinHandle {
    T value{};
    ~WinHandle() {
        if (value && value != reinterpret_cast<T>(INVALID_HANDLE_VALUE))
            Close(value);
    }
    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;
    explicit WinHandle(T v) : value(v) {}
};
std::string win_error(DWORD code = GetLastError()) {
    char* msg = nullptr;
    const auto n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                      FORMAT_MESSAGE_IGNORE_INSERTS,
                                  nullptr, code, 0, reinterpret_cast<char*>(&msg), 0, nullptr);
    std::string result = n ? std::string(msg, n) : "Windows error " + std::to_string(code);
    if (msg)
        LocalFree(msg);
    while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
        result.pop_back();
    return result;
}
CheckResult base(std::string id, std::string component) {
    return {std::move(id), std::move(component),    HealthStatus::Unknown, "",
            Clock::now(),  nlohmann::json::object()};
}
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
} // namespace

ProcessCheck::ProcessCheck(ProcessCheckConfig c) : config_(std::move(c)) {}
std::string ProcessCheck::id() const {
    return config_.id;
}
CheckResult ProcessCheck::execute(std::stop_token stop) {
    auto r = base(id(), "process");
    WinHandle<HANDLE, CloseHandle> snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.value == INVALID_HANDLE_VALUE) {
        r.message = "Cannot enumerate processes: " + win_error();
        return r;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::vector<DWORD> pids;
    if (Process32FirstW(snapshot.value, &entry)) {
        do {
            if (stop.stop_requested()) {
                r.message = "Process check cancelled";
                return r;
            }
            if (_wcsicmp(entry.szExeFile,
                         std::filesystem::path(config_.process_name).wstring().c_str()) == 0)
                pids.push_back(entry.th32ProcessID);
        } while (Process32NextW(snapshot.value, &entry));
    }
    r.status = pids.empty() ? (config_.required ? HealthStatus::Critical : HealthStatus::Warning)
                            : HealthStatus::Ok;
    r.message =
        pids.empty() ? "Configured process is not running" : "Configured process is running";
    r.details = {{"process_name", config_.process_name},
                 {"found", !pids.empty()},
                 {"instance_count", pids.size()},
                 {"pids", pids},
                 {"checked_at", format_utc(r.observed_at)}};
    return r;
}

WindowsServiceCheck::WindowsServiceCheck(ServiceCheckConfig c) : config_(std::move(c)) {}
std::string WindowsServiceCheck::id() const {
    return config_.id;
}
CheckResult WindowsServiceCheck::execute(std::stop_token) {
    auto r = base(id(), "windows-service");
    WinHandle<SC_HANDLE, CloseServiceHandle> scm(
        OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.value) {
        r.message = "Cannot open Service Control Manager: " + win_error();
        r.details["state"] = (GetLastError() == ERROR_ACCESS_DENIED ? "AccessDenied" : "Unknown");
        return r;
    }
    const auto name = std::filesystem::path(config_.service_name).wstring();
    WinHandle<SC_HANDLE, CloseServiceHandle> service(
        OpenServiceW(scm.value, name.c_str(), SERVICE_QUERY_STATUS));
    if (!service.value) {
        const auto code = GetLastError();
        r.status = code == ERROR_SERVICE_DOES_NOT_EXIST
                       ? (config_.required ? HealthStatus::Critical : HealthStatus::Warning)
                       : HealthStatus::Unknown;
        r.message = code == ERROR_SERVICE_DOES_NOT_EXIST
                        ? "Configured service was not found"
                        : "Cannot query configured service: " + win_error(code);
        r.details["state"] = code == ERROR_SERVICE_DOES_NOT_EXIST ? "NotFound"
                             : code == ERROR_ACCESS_DENIED        ? "AccessDenied"
                                                                  : "Unknown";
        return r;
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes{};
    if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes)) {
        r.message = "Cannot query service status: " + win_error();
        r.details["state"] = "Unknown";
        return r;
    }
    std::string state = "Unknown";
    switch (status.dwCurrentState) {
    case SERVICE_RUNNING:
        state = "Running";
        r.status = HealthStatus::Ok;
        break;
    case SERVICE_STOPPED:
        state = "Stopped";
        r.status = config_.required ? HealthStatus::Critical : HealthStatus::Warning;
        break;
    case SERVICE_START_PENDING:
        state = "StartPending";
        r.status = HealthStatus::Warning;
        break;
    case SERVICE_STOP_PENDING:
        state = "StopPending";
        r.status = HealthStatus::Warning;
        break;
    case SERVICE_PAUSED:
        state = "Paused";
        r.status = HealthStatus::Warning;
        break;
    default:
        r.status = HealthStatus::Unknown;
    }
    r.message = "Service state is " + state;
    r.details = {
        {"service_name", config_.service_name}, {"state", state}, {"pid", status.dwProcessId}};
    return r;
}

TcpPortCheck::TcpPortCheck(TcpCheckConfig c) : config_(std::move(c)) {}
std::string TcpPortCheck::id() const {
    return config_.id;
}
CheckResult TcpPortCheck::execute(std::stop_token stop) {
    auto r = base(id(), "tcp");
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        r.message = "Winsock initialization failed";
        return r;
    }
    struct Cleanup {
        ~Cleanup() {
            WSACleanup();
        }
    } cleanup;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* raw = nullptr;
    const auto port = std::to_string(config_.port);
    const auto gai = getaddrinfo(config_.host.c_str(), port.c_str(), &hints, &raw);
    if (gai != 0) {
        r.message = "Address resolution failed: " + std::string(gai_strerrorA(gai));
        return r;
    }
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(raw, freeaddrinfo);
    SOCKET socket_value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_value == INVALID_SOCKET) {
        r.message = "Socket creation failed: " + std::to_string(WSAGetLastError());
        return r;
    }
    struct SocketClose {
        SOCKET s;
        ~SocketClose() {
            closesocket(s);
        }
    } closer{socket_value};
    u_long nonblocking = 1;
    ioctlsocket(socket_value, FIONBIO, &nonblocking);
    const auto started = std::chrono::steady_clock::now();
    int result = connect(socket_value, addresses->ai_addr, static_cast<int>(addresses->ai_addrlen));
    if (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        r.status = HealthStatus::Critical;
        r.message = "TCP connection failed: " + std::to_string(WSAGetLastError());
        return r;
    }
    fd_set write_set, error_set;
    FD_ZERO(&write_set);
    FD_ZERO(&error_set);
    FD_SET(socket_value, &write_set);
    FD_SET(socket_value, &error_set);
    timeval timeout{config_.timeout_ms / 1000, (config_.timeout_ms % 1000) * 1000};
    result = select(0, nullptr, &write_set, &error_set, &timeout);
    if (stop.stop_requested()) {
        r.message = "TCP check cancelled";
        return r;
    }
    int socket_error = 0;
    int length = sizeof(socket_error);
    getsockopt(socket_value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error), &length);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - started)
                             .count();
    const bool connected = result > 0 && FD_ISSET(socket_value, &write_set) && socket_error == 0;
    r.status = connected ? HealthStatus::Ok : HealthStatus::Critical;
    r.message = connected
                    ? "TCP connection succeeded"
                    : (result == 0 ? "TCP connection timed out"
                                   : "TCP connection failed: " + std::to_string(socket_error));
    r.details = {{"host", config_.host}, {"port", config_.port}, {"connect_duration_ms", elapsed}};
    return r;
}

DiskSpaceCheck::DiskSpaceCheck(DiskCheckConfig c) : config_(std::move(c)) {}
std::string DiskSpaceCheck::id() const {
    return config_.id;
}
CheckResult DiskSpaceCheck::execute(std::stop_token) {
    auto r = base(id(), "disk");
    ULARGE_INTEGER available{}, total{}, free{};
    if (!GetDiskFreeSpaceExW(config_.path.c_str(), &available, &total, &free)) {
        r.message = "Cannot query disk space: " + win_error();
        r.details["path"] = config_.path.string();
        return r;
    }
    const double free_percent = total.QuadPart ? 100.0 * static_cast<double>(free.QuadPart) /
                                                     static_cast<double>(total.QuadPart)
                                               : 0;
    const double free_gb = static_cast<double>(free.QuadPart) / (1024.0 * 1024 * 1024);
    if (free_percent < config_.critical_free_percent || free_gb < config_.critical_free_gb)
        r.status = HealthStatus::Critical;
    else if (free_percent < config_.warning_free_percent)
        r.status = HealthStatus::Warning;
    else
        r.status = HealthStatus::Ok;
    r.message = r.status == HealthStatus::Ok ? "Disk space is healthy"
                                             : "Disk free space is below configured threshold";
    r.details = {{"path", config_.path.string()},
                 {"total_bytes", total.QuadPart},
                 {"free_bytes", free.QuadPart},
                 {"free_percent", free_percent},
                 {"used_percent", 100 - free_percent}};
    return r;
}

FileActivityCheck::FileActivityCheck(FileActivityCheckConfig c, ICheckStateStore* state_store)
    : config_(std::move(c)), state_store_(state_store) {
    if (state_store_) {
        if (const auto state = state_store_->load_file_state(config_.id)) {
            previous_size_ = state->size;
            last_change_ = state->last_change_at;
            initialized_ = true;
        }
    }
}
std::string FileActivityCheck::id() const {
    return config_.id;
}
CheckResult FileActivityCheck::execute(std::stop_token stop_token) {
    auto r = base(id(), "file-activity");
    if (stop_token.stop_requested()) {
        r.message = "File activity check cancelled";
        return r;
    }
    std::error_code ec;
    if (!std::filesystem::exists(config_.path, ec)) {
        r.status = HealthStatus::Critical;
        r.message = "Monitored file does not exist";
        r.details = {{"path", config_.path.string()}, {"exists", false}};
        return r;
    }
    std::ifstream readable(config_.path, std::ios::binary);
    if (!readable) {
        r.status = HealthStatus::Critical;
        r.message = "Monitored file is not readable";
        r.details = {{"path", config_.path.string()}, {"readable", false}};
        return r;
    }
    const auto size = std::filesystem::file_size(config_.path, ec);
    if (ec) {
        r.message = "Cannot read file size: " + ec.message();
        return r;
    }
    const auto modified = std::filesystem::last_write_time(config_.path, ec);
    if (ec) {
        r.message = "Cannot read file modification time: " + ec.message();
        return r;
    }
    const auto modified_system = std::chrono::time_point_cast<Clock::duration>(
        modified - decltype(modified)::clock::now() + Clock::now());
    const auto now = Clock::now();
    bool shrunk = false, changed = false;
    if (!initialized_) {
        initialized_ = true;
        last_change_ = now;
    } else {
        changed = size != previous_size_;
        shrunk = size < previous_size_;
        if (changed)
            last_change_ = now;
    }
    previous_size_ = size;
    const auto unchanged =
        std::chrono::duration_cast<std::chrono::seconds>(now - last_change_).count();
    if (shrunk && config_.fail_on_shrink)
        r.status = HealthStatus::Critical;
    else if (unchanged >= config_.critical_unchanged_seconds)
        r.status = HealthStatus::Critical;
    else if (unchanged >= config_.warning_unchanged_seconds)
        r.status = HealthStatus::Warning;
    else
        r.status = HealthStatus::Ok;
    r.message = shrunk    ? "Monitored file shrank unexpectedly"
                : changed ? "Monitored file changed"
                          : "Monitored file is readable";
    r.details = {{"path", config_.path.string()},
                 {"exists", true},
                 {"readable", true},
                 {"size_bytes", size},
                 {"last_modified_at", format_utc(modified_system)},
                 {"changed", changed},
                 {"shrunk", shrunk},
                 {"unchanged_seconds", unchanged}};
    if (state_store_) {
        state_store_->save_file_state({config_.id, size, modified_system, last_change_});
    }
    return r;
}

LogPatternCheck::LogPatternCheck(LogCheckConfig c, ICheckStateStore* state_store)
    : config_(std::move(c)), state_store_(state_store) {
    if (state_store_) {
        if (const auto state = state_store_->load_log_state(config_.id)) {
            offset_ = state->offset;
            file_id_ = state->file_id;
            volume_serial_ = state->volume_serial;
            identity_initialized_ = true;
        }
    }
}
std::string LogPatternCheck::id() const {
    return config_.id;
}
CheckResult LogPatternCheck::execute(std::stop_token stop) {
    auto r = base(id(), "log");
    std::error_code ec;
    if (!std::filesystem::exists(config_.path, ec)) {
        r.status = HealthStatus::Warning;
        r.message = "Log file does not exist";
        r.details["path"] = config_.path.string();
        return r;
    }
    WinHandle<HANDLE, CloseHandle> handle(CreateFileW(
        config_.path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (handle.value == INVALID_HANDLE_VALUE) {
        r.message = "Cannot open log file without locking it: " + win_error();
        return r;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle.value, &info)) {
        r.message = "Cannot inspect log file identity: " + win_error();
        return r;
    }
    const std::uint64_t file_id =
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    if (identity_initialized_ &&
        (file_id != file_id_ || info.dwVolumeSerialNumber != volume_serial_))
        offset_ = 0;
    identity_initialized_ = true;
    file_id_ = file_id;
    volume_serial_ = info.dwVolumeSerialNumber;
    const auto size = std::filesystem::file_size(config_.path, ec);
    if (ec) {
        r.message = "Cannot inspect log file: " + ec.message();
        return r;
    }
    if (size < offset_)
        offset_ = 0;
    const auto available = size - offset_;
    const auto read_size = std::min<std::uintmax_t>(available, config_.max_read_bytes);
    std::ifstream input(config_.path, std::ios::binary);
    input.seekg(static_cast<std::streamoff>(offset_));
    std::string data(static_cast<std::size_t>(read_size), '\0');
    input.read(data.data(), static_cast<std::streamsize>(data.size()));
    data.resize(static_cast<std::size_t>(input.gcount()));
    offset_ += data.size();
    if (state_store_) {
        state_store_->save_log_state({config_.id, offset_, file_id_, volume_serial_, Clock::now()});
    }
    if (stop.stop_requested()) {
        r.message = "Log check cancelled";
        return r;
    }
    const auto haystack = config_.case_sensitive ? data : lower(data);
    nlohmann::json matches = nlohmann::json::array();
    HealthStatus worst = HealthStatus::Ok;
    for (const auto& g : config_.groups)
        for (const auto& p : g.patterns) {
            const auto needle = config_.case_sensitive ? p : lower(p);
            if (haystack.find(needle) != std::string::npos) {
                matches.push_back({{"group", g.name}, {"pattern", p}, {"severity", g.severity}});
                if (static_cast<int>(g.severity) > static_cast<int>(worst))
                    worst = g.severity;
                break;
            }
        }
    r.status = worst;
    r.message = matches.empty() ? "No configured log patterns found"
                                : "Configured error patterns found in new log data";
    r.details = {{"path", config_.path.string()},
                 {"bytes_read", data.size()},
                 {"next_offset", offset_},
                 {"matches", matches}};
    return r;
}

} // namespace scadaguard
