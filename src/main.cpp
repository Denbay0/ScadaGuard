#include "scadaguard/application.hpp"
#include "scadaguard/config.hpp"
#include "scadaguard/service_host.hpp"
#include "scadaguard/version.hpp"

#include <csignal>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <memory>
#include <nlohmann/json.hpp>
#include <spdlog/fmt/fmt.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <stop_token>
#include <stdexcept>
#include <string>

namespace {
std::stop_source* console_stop = nullptr;
void signal_handler(int) {
    if (console_stop)
        console_stop->request_stop();
}
struct Args {
    std::string mode;
    std::filesystem::path config = scadaguard::default_config_path();
};
Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string v = argv[i];
        if (v == "--config") {
            if (++i >= argc)
                throw std::invalid_argument("--config requires a path");
            a.config = argv[i];
        } else if (a.mode.empty())
            a.mode = v;
        else
            throw std::invalid_argument("unexpected argument: " + v);
    }
    if (a.mode.empty())
        throw std::invalid_argument("mode is required");
    return a;
}
class JsonLogFormatter final : public spdlog::formatter {
  public:
    explicit JsonLogFormatter(const scadaguard::AgentConfig& agent) : agent_(agent) {}

    void format(const spdlog::details::log_msg& message,
                spdlog::memory_buf_t& destination) override {
        const auto level = spdlog::level::to_string_view(message.level);
        const nlohmann::json record{
            {"timestamp", scadaguard::format_utc(message.time)},
            {"level", std::string(level.data(), level.size())},
            {"component", "agent"},
            {"agent_id", agent_.agent_id},
            {"site_id", agent_.site_id},
            {"host_id", agent_.host_id},
            {"message", std::string(message.payload.data(), message.payload.size())},
        };
        fmt::format_to(std::back_inserter(destination), "{}\n", record.dump());
    }

    std::unique_ptr<spdlog::formatter> clone() const override {
        return std::make_unique<JsonLogFormatter>(agent_);
    }

  private:
    scadaguard::AgentConfig agent_;
};

void configure_logging(const scadaguard::AppConfig& config) {
    const auto& logging = config.logging;
    std::filesystem::create_directories(logging.directory);
    auto logger =
        spdlog::rotating_logger_mt("scadaguard", (logging.directory / "scadaguard.log").string(),
                                   logging.max_file_size_mb * 1024 * 1024, logging.max_files);
    if (logging.format == "json") {
        logger->set_formatter(std::make_unique<JsonLogFormatter>(config.agent));
    } else {
        logger->set_pattern("%Y-%m-%dT%H:%M:%S.%e [%l] [agent] %v");
    }
    logger->set_level(spdlog::level::from_str(logging.level));
    spdlog::set_default_logger(std::move(logger));
}
} // namespace
int main(int argc, char** argv) {
    try {
        const auto args = parse_args(argc, argv);
        if (args.mode == "--version") {
            std::cout << "ScadaGuard Agent " << scadaguard::agent_version << " (protocol "
                      << scadaguard::protocol_version << ", " << scadaguard::build_type << ", "
                      << scadaguard::build_architecture << ")\n";
            return 0;
        }
        if (args.mode == "--install") {
            scadaguard::WindowsServiceHost::install(std::filesystem::absolute(argv[0]),
                                                    std::filesystem::absolute(args.config));
            std::cout << "ScadaGuard Agent service installed\n";
            return 0;
        }
        if (args.mode == "--uninstall") {
            scadaguard::WindowsServiceHost::uninstall();
            std::cout << "ScadaGuard Agent service uninstalled\n";
            return 0;
        }
        auto config = scadaguard::load_config(args.config);
        config.agent.runtime_mode = args.mode.starts_with("--") ? args.mode.substr(2) : args.mode;
        if (args.mode == "--validate-config") {
            std::cout << "Configuration is valid: " << args.config.string() << '\n';
            return 0;
        }
        configure_logging(config);
        scadaguard::Application app(std::move(config));
        if (args.mode == "--once") {
            std::cout << app.run_once().dump(2) << '\n';
            return 0;
        }
        if (args.mode == "--console") {
            std::stop_source stop;
            console_stop = &stop;
            std::signal(SIGINT, signal_handler);
            std::signal(SIGTERM, signal_handler);
            app.run(stop.get_token());
            console_stop = nullptr;
            return 0;
        }
        if (args.mode == "--service") {
            scadaguard::WindowsServiceHost host([&app](std::stop_token stop) { app.run(stop); });
            return host.run();
        }
        throw std::invalid_argument("unknown mode: " + args.mode);
    } catch (const std::exception& e) {
        try {
            spdlog::critical("fatal: {}", e.what());
        } catch (...) {
        }
        std::cerr << "ScadaGuard: " << e.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "ScadaGuard: unknown fatal error\n";
        return 1;
    }
}
