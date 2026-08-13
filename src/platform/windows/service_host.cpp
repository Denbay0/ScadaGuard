#include "scadaguard/service_host.hpp"
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <chrono>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <windows.h>
#include <winsvc.h>

namespace scadaguard {
namespace {
constexpr wchar_t service_name[] = L"ScadaGuardAgent";
constexpr wchar_t display_name[] = L"ScadaGuard Agent";
std::runtime_error error(const char* what) {
    return std::runtime_error(std::string(what) + " (Windows error " +
                              std::to_string(GetLastError()) + ")");
}
} // namespace
WindowsServiceHost* WindowsServiceHost::active_ = nullptr;
WindowsServiceHost::WindowsServiceHost(Runner r) : runner_(std::move(r)) {}
int WindowsServiceHost::run() {
    if (active_)
        throw std::logic_error("a service host is already active");
    active_ = this;
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<wchar_t*>(service_name), service_main_callback},
                                    {nullptr, nullptr}};
    const BOOL ok = StartServiceCtrlDispatcherW(table);
    active_ = nullptr;
    if (!ok)
        throw error("StartServiceCtrlDispatcher failed");
    return 0;
}
void __stdcall WindowsServiceHost::service_main_callback(unsigned long, wchar_t**) {
    if (active_)
        active_->service_main();
}
unsigned long __stdcall WindowsServiceHost::control_callback(unsigned long control, unsigned long,
                                                             void*, void* context) {
    auto* self = static_cast<WindowsServiceHost*>(context);
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        self->set_status(SERVICE_STOP_PENDING, 0, 10000);
        self->stop_.request_stop();
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}
void WindowsServiceHost::set_status(unsigned long state, unsigned long exit_code,
                                    unsigned long wait_hint) {
    SERVICE_STATUS value{};
    value.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    value.dwCurrentState = state;
    value.dwWin32ExitCode = exit_code;
    value.dwWaitHint = wait_hint;
    value.dwControlsAccepted =
        state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    SetServiceStatus(static_cast<SERVICE_STATUS_HANDLE>(status_handle_), &value);
}
void WindowsServiceHost::service_main() {
    status_handle_ = RegisterServiceCtrlHandlerExW(service_name, control_callback, this);
    if (!status_handle_)
        return;
    set_status(SERVICE_START_PENDING, 0, 10000);
    try {
        set_status(SERVICE_RUNNING);
        runner_(stop_.get_token());
        set_status(SERVICE_STOPPED);
    } catch (const std::exception& e) {
        spdlog::critical("Windows Service failed: {}", e.what());
        set_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
    } catch (...) {
        spdlog::critical("Windows Service failed with an unknown exception");
        set_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
    }
}
void WindowsServiceHost::install(const std::filesystem::path& exe,
                                 const std::filesystem::path& config) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm)
        throw error("OpenSCManager failed");
    struct Close {
        SC_HANDLE h;
        ~Close() {
            CloseServiceHandle(h);
        }
    } close_scm{scm};
    const std::wstring command =
        L"\"" + exe.wstring() + L"\" --service --config \"" + config.wstring() + L"\"";
    SC_HANDLE service =
        CreateServiceW(scm, service_name, display_name, SERVICE_ALL_ACCESS,
                       SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                       command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!service)
        throw error("CreateService failed");
    CloseServiceHandle(service);
}
void WindowsServiceHost::uninstall() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        throw error("OpenSCManager failed");
    struct Close {
        SC_HANDLE h;
        ~Close() {
            CloseServiceHandle(h);
        }
    } close_scm{scm};
    SC_HANDLE service =
        OpenServiceW(scm, service_name, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!service) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
            return;
        throw error("OpenService failed");
    }
    Close close_service{service};
    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    for (int i = 0; i < 50; ++i) {
        SERVICE_STATUS_PROCESS current{};
        DWORD bytes{};
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<BYTE*>(&current), sizeof(current), &bytes) ||
            current.dwCurrentState == SERVICE_STOPPED)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!DeleteService(service) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
        throw error("DeleteService failed");
}
} // namespace scadaguard
