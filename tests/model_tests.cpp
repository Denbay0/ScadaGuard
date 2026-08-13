#include "scadaguard/model.hpp"
#include <catch2/catch_test_macros.hpp>

using namespace scadaguard;
TEST_CASE("core models round trip through JSON") {
    const auto now = parse_utc("2026-08-05T10:11:12Z");
    CheckResult original{"disk", "disk", HealthStatus::Warning, "low", now, {{"free", 4}}};
    auto restored = nlohmann::json(original).get<CheckResult>();
    REQUIRE(restored.check_id == original.check_id);
    REQUIRE(restored.status == HealthStatus::Warning);
    REQUIRE(format_utc(restored.observed_at) == "2026-08-05T10:11:12Z");
    SignalSample sample{"s", 42, now, now, "Good"};
    REQUIRE(nlohmann::json(sample).get<SignalSample>().value == 42);
    Incident incident{"i", "k", "c", HealthStatus::Critical, "t", "d", now, std::nullopt, true, {}};
    REQUIRE(nlohmann::json(incident).get<Incident>().active);
}
TEST_CASE("invalid health status is rejected") {
    REQUIRE_THROWS_AS(health_status_from_string("broken"), std::invalid_argument);
}
TEST_CASE("generated identifiers are UUID version 4") {
    const auto first = generate_uuid_v4();
    const auto second = generate_uuid_v4();
    REQUIRE(first.size() == 36);
    REQUIRE(first[14] == '4');
    REQUIRE((first[19] == '8' || first[19] == '9' || first[19] == 'a' || first[19] == 'b'));
    REQUIRE(first != second);
}
