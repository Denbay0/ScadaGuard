#pragma once

#include "scadaguard/model.hpp"

#include <filesystem>
#include <stop_token>
#include <utility>
#include <vector>

namespace scadaguard {

class ICurrentDataSource {
  public:
    virtual ~ICurrentDataSource() = default;
    virtual std::vector<SignalSample> read_current(std::stop_token) = 0;
};
class IArchiveDataSource {
  public:
    virtual ~IArchiveDataSource() = default;
    virtual std::vector<SignalSample> read_archive(TimePoint from, TimePoint to,
                                                   std::stop_token) = 0;
};

class MockCurrentDataSource final : public ICurrentDataSource {
  public:
    explicit MockCurrentDataSource(std::vector<SignalSample> samples = {})
        : samples_(std::move(samples)) {}
    std::vector<SignalSample> read_current(std::stop_token) override;
    void set_samples(std::vector<SignalSample> samples);

  private:
    std::vector<SignalSample> samples_;
};
class MockArchiveDataSource final : public IArchiveDataSource {
  public:
    explicit MockArchiveDataSource(std::vector<SignalSample> samples = {})
        : samples_(std::move(samples)) {}
    std::vector<SignalSample> read_archive(TimePoint, TimePoint, std::stop_token) override;

  private:
    std::vector<SignalSample> samples_;
};
class CsvReplayDataSource final : public ICurrentDataSource, public IArchiveDataSource {
  public:
    explicit CsvReplayDataSource(std::filesystem::path path);
    std::vector<SignalSample> read_current(std::stop_token) override;
    std::vector<SignalSample> read_archive(TimePoint, TimePoint, std::stop_token) override;

  private:
    std::vector<SignalSample> read_all(std::stop_token) const;
    std::filesystem::path path_;
};
class OpcUaCurrentDataSource final : public ICurrentDataSource {
  public:
    std::vector<SignalSample> read_current(std::stop_token) override;
};

struct SqliteArchiveOptions {
    bool enabled{};
    std::filesystem::path database_path;
    std::string table, signal_id_column, timestamp_column, value_column, quality_column;
};
class SqliteArchiveDataSource final : public IArchiveDataSource {
  public:
    explicit SqliteArchiveDataSource(SqliteArchiveOptions options);
    std::vector<SignalSample> read_archive(TimePoint, TimePoint, std::stop_token) override;
    static bool valid_identifier(const std::string& value);

  private:
    SqliteArchiveOptions options_;
};

} // namespace scadaguard
