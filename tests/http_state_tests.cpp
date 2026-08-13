#include "scadaguard/http_server.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace scadaguard;

TEST_CASE("agent health is unknown when required integrations are unconfigured") {
    AgentConfig agent{"agent", "site", "host"};
    ConfigurationStatus configuration;
    configuration.loaded = true;
    configuration.loaded_at = Clock::now();
    configuration.unconfigured_subsystems = {"opcua"};
    AgentState state(agent, configuration, generate_uuid_v4());
    state.update({{"check", "system", HealthStatus::Ok, "ok", Clock::now(), {}}}, {}, {}, 0,
                 std::nullopt);

    REQUIRE(state.health().at("status") == HealthStatus::Unknown);
}

TEST_CASE("Prometheus label values are escaped") {
    AgentConfig agent{"agent", "site", "host"};
    ConfigurationStatus configuration;
    configuration.loaded = true;
    configuration.loaded_at = Clock::now();
    AgentState state(agent, configuration, generate_uuid_v4());
    state.update(
        {{"quoted\"check\\name\n", "component\"", HealthStatus::Ok, "ok", Clock::now(), {}}}, {},
        {}, 2, Clock::now());

    const auto metrics = state.metrics();
    REQUIRE(metrics.find("quoted\\\"check\\\\name\\n") != std::string::npos);
    REQUIRE(metrics.find("scadaguard_outbound_queue_size 2") != std::string::npos);
}

TEST_CASE("configuration status reports real metadata") {
    AgentConfig agent{"agent", "site", "host"};
    ConfigurationStatus configuration;
    configuration.loaded = true;
    configuration.path = "C:\\ProgramData\\ScadaGuard\\config.json";
    configuration.hash = "fnv1a64-test";
    configuration.loaded_at = Clock::now();
    AgentState state(agent, configuration, generate_uuid_v4());

    const auto status = state.configuration_status();
    REQUIRE(status.at("loaded") == true);
    REQUIRE(status.at("path") == configuration.path);
    REQUIRE(status.at("hash") == configuration.hash);
}

TEST_CASE("agent state exposes the latest discovery report") {
    AgentState state(AgentConfig{"agent", "site", "host"}, ConfigurationStatus{},
                     generate_uuid_v4());
    state.update_discovery({{"scan_id", "scan-1"},
                            {"masterscada", {{"detected", true}, {"status", "detected"}}}});
    REQUIRE(state.discovery().at("scan_id") == "scan-1");
    REQUIRE(state.discovery().at("masterscada").at("detected") == true);
}
