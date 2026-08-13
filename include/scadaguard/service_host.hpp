#pragma once

#include <filesystem>
#include <functional>
#include <stop_token>

namespace scadaguard {
class WindowsServiceHost {
  public:
    using Runner = std::function<void(std::stop_token)>;
    explicit WindowsServiceHost(Runner runner);
    int run();
    static void install(const std::filesystem::path& exe, const std::filesystem::path& config);
    static void uninstall();

  private:
    void service_main();
    void set_status(unsigned long state, unsigned long exit_code = 0, unsigned long wait_hint = 0);
    static void __stdcall service_main_callback(unsigned long, wchar_t**);
    static unsigned long __stdcall control_callback(unsigned long, unsigned long, void*, void*);
    Runner runner_;
    std::stop_source stop_;
    void* status_handle_{};
    static WindowsServiceHost* active_;
};
} // namespace scadaguard
