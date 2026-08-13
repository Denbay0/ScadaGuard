#pragma once

#include "scadaguard/discovery.hpp"

namespace scadaguard {

class WindowsDiscoveryEnvironment final : public IDiscoveryEnvironment {
  public:
    std::vector<ProcessDiscoveryRecord> processes(std::stop_token stop) const override;
    std::vector<ServiceDiscoveryRecord> services(std::stop_token stop) const override;
    std::vector<InstalledApplicationRecord>
    installed_applications(std::stop_token stop) const override;
    std::vector<std::filesystem::path> standard_roots() const override;
    std::vector<DirectoryEntryRecord>
    list_directory(const std::filesystem::path& path) const override;
    std::optional<std::string> read_prefix(const std::filesystem::path& path,
                                           std::size_t maximum_bytes) const override;
    std::optional<std::string> read_tail(const std::filesystem::path& path,
                                         std::size_t maximum_bytes) const override;
    SqliteInspection inspect_sqlite(const std::filesystem::path& path) const override;
};

} // namespace scadaguard
