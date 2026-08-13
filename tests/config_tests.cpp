#include "scadaguard/config.hpp"
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
    REQUIRE(c.status.loaded);
    REQUIRE(c.status.hash.starts_with("fnv1a64-"));
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
