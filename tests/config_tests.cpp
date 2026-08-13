#include "scadaguard/config.hpp"
#include "scadaguard/central_configuration.hpp"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
using namespace scadaguard;
namespace {
nlohmann::json minimal() {
    return {{"agent", {{"agent_id", "a"}, {"site_id", "s"}, {"host_id", "h"}}},
            {"local_api", {{"bind_address", "127.0.0.1"}}},
            {"signals", nlohmann::json::array()}};
}
} // namespace
TEST_CASE("minimal configuration is valid") {
    auto c = parse_config(minimal());
    REQUIRE(c.agent.poll_interval_seconds == 30);
    REQUIRE(c.local_api.port == 9180);
    REQUIRE(c.discovery.enabled);
    REQUIRE(c.discovery.scheduled_interval_hours == 6);
    REQUIRE(c.status.loaded);
    REQUIRE(c.status.hash.starts_with("fnv1a64-"));
}
TEST_CASE("discovery limits and hints are configurable") {
    auto j = minimal();
    j["discovery"] = {{"scheduled_interval_hours", 12},
                      {"keywords", {"custom-runtime"}},
                      {"additional_roots", {"C:\\Vendor\\Runtime"}},
                      {"maximum_directories", 25},
                      {"maximum_depth", 2},
                      {"maximum_duration_seconds", 4}};
    const auto c = parse_config(j);
    REQUIRE(c.discovery.keywords == std::vector<std::string>{"custom-runtime"});
    REQUIRE(c.discovery.additional_roots.front() == "C:\\Vendor\\Runtime");
    REQUIRE(c.discovery.maximum_directories == 25);
    REQUIRE(c.discovery.maximum_depth == 2);
}

TEST_CASE("invalid discovery limits are rejected") {
    auto j = minimal();
    j["discovery"] = {{"maximum_duration_seconds", 0}};
    REQUIRE_THROWS_WITH(parse_config(j),
                        Catch::Matchers::ContainsSubstring("maximum_duration_seconds"));
}
TEST_CASE("configuration hash is deterministic and changes with content") {
    const auto original = minimal();
    auto changed = original;
    changed["agent"]["host_id"] = "different";

    REQUIRE(configuration_hash(original) == configuration_hash(original));
    REQUIRE(configuration_hash(original) != configuration_hash(changed));
}
TEST_CASE("signal maximum must exceed minimum") {
    auto j = minimal();
    j["signals"].push_back({{"signal_id", "x"}, {"minimum", 10}, {"maximum", 1}});
    REQUIRE_THROWS_WITH(parse_config(j), Catch::Matchers::ContainsSubstring("signals[0].maximum"));
}
TEST_CASE("local API cannot be exposed") {
    auto j = minimal();
    j["local_api"]["bind_address"] = "0.0.0.0";
    REQUIRE_THROWS_WITH(parse_config(j), Catch::Matchers::ContainsSubstring("127.0.0.1"));
}
TEST_CASE("production reporter requires HTTPS") {
    auto j = minimal();
    j["central_server"] = {{"enabled", true}, {"production", true}, {"base_url", "http://example"}};
    REQUIRE_THROWS_WITH(parse_config(j), Catch::Matchers::ContainsSubstring("HTTPS"));
}

TEST_CASE("central configuration validates its safe read-only subset") {
    const nlohmann::json configuration{{"confirmed_archive", R"(D:\SCADA\archive.db)"},
                                       {"confirmed_logs", nlohmann::json::array()},
                                       {"monitoring_interval_seconds", 30}};
    const auto value = validate_desired_agent_configuration(
        {{"config_version", 2},
         {"config_hash", desired_configuration_hash(configuration)},
         {"configuration", configuration}});
    REQUIRE(value.version == 2);
    REQUIRE(value.confirmed_archive == R"(D:\SCADA\archive.db)");
}

TEST_CASE("invalid central configuration is rejected before activation") {
    const nlohmann::json configuration{{"confirmed_archive", R"(\\server\share\archive.db)"}};
    REQUIRE_THROWS_WITH(validate_desired_agent_configuration(
                            {{"config_version", 1},
                             {"config_hash", desired_configuration_hash(configuration)},
                             {"configuration", configuration}}),
                        Catch::Matchers::ContainsSubstring("bounded local path"));
}

TEST_CASE("central archive mapping requires a confirmed path and safe identifiers") {
    const nlohmann::json mapping{{"table", "history_2026"},
                                 {"timestamp_column", "recorded_at"},
                                 {"signal_id_column", "item_id"},
                                 {"value_column", "value"},
                                 {"quality_column", nullptr}};
    const nlohmann::json configuration{{"confirmed_archive", R"(D:\SCADA\archive.db)"},
                                       {"archive_mapping", mapping}};
    const auto value = validate_desired_agent_configuration(
        {{"config_version", 4},
         {"config_hash", desired_configuration_hash(configuration)},
         {"configuration", configuration}});
    REQUIRE(value.archive_mapping.at("table") == "history_2026");

    auto invalid = configuration;
    invalid["archive_mapping"]["table"] = "history; DROP TABLE x";
    REQUIRE_THROWS_WITH(
        validate_desired_agent_configuration({{"config_version", 5},
                                              {"config_hash", desired_configuration_hash(invalid)},
                                              {"configuration", invalid}}),
        Catch::Matchers::ContainsSubstring("invalid identifier"));
}

TEST_CASE("central configuration SHA-256 matches server canonical JSON") {
    const auto configuration = nlohmann::json::parse(
        R"({"confirmed_logs":[],"monitored_signals":["\u0422\u0435\u043c\u043f\u0435\u0440\u0430\u0442\u0443\u0440\u0430"]})");
    REQUIRE(desired_configuration_hash(configuration) ==
            "sha256-12a0888d514eb935fa04b5eefb2b31a072c64209b63df6da984319e7ec5f26c6");
}

TEST_CASE("central configuration validates signal thresholds and monitoring interval") {
    const nlohmann::json configuration{
        {"monitored_signals", {"temperature"}},
        {"thresholds", {{"temperature", {{"minimum", 0.0}, {"maximum", 100.0}}}}},
        {"monitoring_interval_seconds", 15}};
    const auto value = validate_desired_agent_configuration(
        {{"config_version", 3},
         {"config_hash", desired_configuration_hash(configuration)},
         {"configuration", configuration}});
    REQUIRE(value.monitored_signals == std::vector<std::string>{"temperature"});
    REQUIRE(value.monitoring_interval_seconds == 15);
    REQUIRE(value.thresholds.at("temperature").at("maximum") == 100.0);
}
