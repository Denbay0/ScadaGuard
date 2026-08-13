#include "scadaguard/data_sources.hpp"
#include <catch2/catch_test_macros.hpp>
using namespace scadaguard;
using namespace std::chrono_literals;
TEST_CASE("mock sources return configured samples") {
    auto t = Clock::now();
    SignalSample s{"x", 1, t, t, "Good"};
    MockCurrentDataSource current({s});
    MockArchiveDataSource archive({s});
    REQUIRE(current.read_current({}).size() == 1);
    REQUIRE(archive.read_archive(t - 1s, t + 1s, {}).size() == 1);
}
TEST_CASE("OPC UA stub fails safely") {
    OpcUaCurrentDataSource source;
    REQUIRE_THROWS_WITH(source.read_current({}), "OPC UA data source is not configured");
}
TEST_CASE("SQLite identifiers use strict whitelist") {
    REQUIRE(SqliteArchiveDataSource::valid_identifier("signal_id"));
    REQUIRE_FALSE(SqliteArchiveDataSource::valid_identifier("signal;DROP TABLE x"));
    REQUIRE_FALSE(SqliteArchiveDataSource::valid_identifier("a.b"));
}
