#include "scadaguard/data_quality.hpp"
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
using namespace scadaguard;
using namespace std::chrono_literals;
namespace {
const auto now = parse_utc("2026-08-05T10:00:00Z");
SignalRule rule() {
    SignalRule r;
    r.signal_id = "s";
    r.minimum = 0;
    r.maximum = 100;
    r.invalid_sentinels = {-32768};
    r.max_age_seconds = 60;
    r.frozen_after_seconds = 10;
    r.frozen_epsilon = .1;
    r.max_rate_per_second = 5;
    r.expected_period_seconds = 5;
    r.missing_period_multiplier = 3;
    r.archive_delay_seconds = 30;
    r.archive_match_window_seconds = 10;
    r.archive_absolute_tolerance = .1;
    r.archive_relative_tolerance = .001;
    return r;
}
SignalSample sample(double value, TimePoint t = now, std::string quality = "Good") {
    return {"s", value, t, t, std::move(quality)};
}
bool has(const std::vector<CheckResult>& r, const std::string& type) {
    return std::any_of(r.begin(), r.end(),
                       [&](const auto& v) { return v.details.value("problem_type", "") == type; });
}
} // namespace
TEST_CASE("stale value is detected") {
    DataQualityAnalyzer a;
    REQUIRE(has(a.analyze({sample(1, now - 61s)}, {rule()}, now), "stale"));
}
TEST_CASE("bad quality is detected") {
    DataQualityAnalyzer a;
    REQUIRE(has(a.analyze({sample(1, now, "Bad")}, {rule()}, now), "bad_quality"));
}
TEST_CASE("out of range is detected") {
    DataQualityAnalyzer a;
    REQUIRE(has(a.analyze({sample(101)}, {rule()}, now), "out_of_range"));
}
TEST_CASE("invalid sentinel is detected") {
    DataQualityAnalyzer a;
    REQUIRE(has(a.analyze({sample(-32768)}, {rule()}, now), "invalid_sentinel"));
}
TEST_CASE("frozen value is detected after threshold") {
    DataQualityAnalyzer a;
    auto r = rule();
    a.analyze({sample(10, now - 11s)}, {r}, now - 11s);
    REQUIRE(has(a.analyze({sample(10.05, now)}, {r}, now), "frozen"));
}
TEST_CASE("change within epsilon keeps frozen timer but is initially allowed") {
    DataQualityAnalyzer a;
    auto r = rule();
    a.analyze({sample(10, now - 5s)}, {r}, now - 5s);
    REQUIRE_FALSE(has(a.analyze({sample(10.05, now)}, {r}, now), "frozen"));
}
TEST_CASE("excessive rate is detected") {
    DataQualityAnalyzer a;
    auto r = rule();
    a.analyze({sample(1, now - 1s)}, {r}, now - 1s);
    REQUIRE(has(a.analyze({sample(20, now)}, {r}, now), "excessive_rate"));
}
TEST_CASE("non monotonic timestamp is detected") {
    DataQualityAnalyzer a;
    auto r = rule();
    a.analyze({sample(1, now)}, {r}, now);
    REQUIRE(has(a.analyze({sample(2, now - 1s)}, {r}, now), "non_monotonic_timestamp"));
}
TEST_CASE("missing samples are detected") {
    DataQualityAnalyzer a;
    auto r = rule();
    a.analyze({sample(1, now - 20s)}, {r}, now - 20s);
    REQUIRE(has(a.analyze({sample(2, now)}, {r}, now), "missing_samples"));
}
TEST_CASE("online and archive match within tolerance") {
    DataQualityAnalyzer a;
    auto r = rule();
    auto current = sample(10, now - 31s);
    auto archive = sample(10.05, now - 30s);
    REQUIRE(a.compare_archive({current}, {archive}, {r}, now).empty());
}
TEST_CASE("online and archive mismatch is detected") {
    DataQualityAnalyzer a;
    auto r = rule();
    REQUIRE(has(a.compare_archive({sample(10, now - 31s)}, {sample(20, now - 31s)}, {r}, now),
                "archive_mismatch"));
}
TEST_CASE("archive delay suppresses mismatch") {
    DataQualityAnalyzer a;
    auto r = rule();
    REQUIRE(a.compare_archive({sample(10, now - 29s)}, {}, {r}, now).empty());
}
