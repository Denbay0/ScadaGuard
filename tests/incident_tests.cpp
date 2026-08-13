#include "scadaguard/incident_manager.hpp"
#include <catch2/catch_test_macros.hpp>
using namespace scadaguard;
using namespace std::chrono_literals;
namespace {
const auto now = parse_utc("2026-08-05T10:00:00Z");
CheckResult problem() {
    return {"disk", "disk", HealthStatus::Critical, "low", now, {{"problem_type", "space"}}};
}
CheckResult ok() {
    return {"disk", "disk", HealthStatus::Ok, "ok", now, {{"problem_type", "space"}}};
}
} // namespace
TEST_CASE("incident is created without duplication") {
    IncidentManager m("site", "host");
    REQUIRE(m.process(problem(), now).front().type == "opened");
    REQUIRE(m.process(problem(), now + 1s).empty());
    REQUIRE(m.active_incidents().size() == 1);
    REQUIRE(m.active_incidents()[0].details["occurrences"] == 2);
}
TEST_CASE("incident closes after recovery") {
    IncidentManager m("site", "host");
    m.process(problem(), now);
    auto events = m.process(ok(), now + 1s);
    REQUIRE(events.size() == 1);
    REQUIRE(events[0].type == "recovered");
    REQUIRE(m.active_incidents().empty());
}
TEST_CASE("notification cooldown is respected") {
    IncidentManager m("site", "host", IncidentPolicy{0s, 0s, 10s});
    m.process(problem(), now);
    REQUIRE(m.process(problem(), now + 9s).empty());
    REQUIRE(m.process(problem(), now + 10s).front().type == "reminder");
}
