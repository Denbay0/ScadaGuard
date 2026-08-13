#include "scadaguard/central_configuration.hpp"
#include "scadaguard/data_sources.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <ranges>
#include <set>
#include <stdexcept>
#include <iomanip>
#include <memory>
#include <sstream>

#include <openssl/evp.h>

namespace scadaguard {
namespace {

std::filesystem::path validate_local_path(const std::string& value) {
    const std::filesystem::path path(value);
    const auto normalized = path.lexically_normal();
    const auto text = normalized.string();
    const auto root = normalized.root_path().string();
    if (!normalized.is_absolute() || text.starts_with("\\\\") || text == root) {
        throw std::invalid_argument("central configuration path must be a bounded local path");
    }
    auto lowered = text;
    std::ranges::transform(lowered, lowered.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    if (lowered == "c:\\windows" || lowered.starts_with("c:\\windows\\") ||
        lowered == "c:\\users" || lowered.starts_with("c:\\users\\")) {
        throw std::invalid_argument("central configuration path targets a protected directory");
    }
    return normalized;
}

} // namespace

DesiredAgentConfiguration validate_desired_agent_configuration(const nlohmann::json& value) {
    if (!value.is_object()) {
        throw std::invalid_argument("desired agent configuration must be an object");
    }
    DesiredAgentConfiguration result;
    result.version = value.at("config_version").get<std::uint64_t>();
    result.hash = value.at("config_hash").get<std::string>();
    if (result.version == 0 || !result.hash.starts_with("sha256-") || result.hash.size() != 71) {
        throw std::invalid_argument("desired agent configuration version or hash is invalid");
    }
    const auto& configuration = value.at("configuration");
    if (!configuration.is_object()) {
        throw std::invalid_argument("desired agent configuration payload must be an object");
    }
    if (desired_configuration_hash(configuration) != result.hash) {
        throw std::invalid_argument("desired agent configuration hash does not match payload");
    }
    const std::set<std::string> allowed{"confirmed_archive", "archive_mapping",
                                        "confirmed_logs",    "monitored_signals",
                                        "thresholds",        "monitoring_interval_seconds",
                                        "server_url",        "rescan_requested_at"};
    for (const auto& [key, _] : configuration.items()) {
        if (!allowed.contains(key)) {
            throw std::invalid_argument("central configuration contains unsupported field: " + key);
        }
    }
    if (configuration.contains("confirmed_archive") &&
        !configuration.at("confirmed_archive").is_null()) {
        result.confirmed_archive =
            validate_local_path(configuration.at("confirmed_archive").get<std::string>());
    }
    if (configuration.contains("confirmed_logs")) {
        for (const auto& item :
             configuration.at("confirmed_logs").get<std::vector<std::string>>()) {
            result.confirmed_logs.push_back(validate_local_path(item));
        }
    }
    if (configuration.contains("archive_mapping") &&
        !configuration.at("archive_mapping").is_null()) {
        const auto& mapping = configuration.at("archive_mapping");
        const std::set<std::string> fields{"table", "timestamp_column", "signal_id_column",
                                           "value_column", "quality_column"};
        if (!result.confirmed_archive || !mapping.is_object()) {
            throw std::invalid_argument(
                "archive_mapping requires a confirmed read-only archive path");
        }
        for (const auto& [key, value] : mapping.items()) {
            if (!fields.contains(key) || (!value.is_string() && !value.is_null())) {
                throw std::invalid_argument("archive_mapping contains an unsupported field");
            }
        }
        for (const auto* required :
             {"table", "timestamp_column", "signal_id_column", "value_column"}) {
            if (!mapping.contains(required) || !SqliteArchiveDataSource::valid_identifier(
                                                   mapping.at(required).get<std::string>())) {
                throw std::invalid_argument("archive_mapping contains an invalid identifier");
            }
        }
        if (mapping.contains("quality_column") && !mapping.at("quality_column").is_null() &&
            !SqliteArchiveDataSource::valid_identifier(
                mapping.at("quality_column").get<std::string>())) {
            throw std::invalid_argument("archive_mapping quality column is invalid");
        }
        result.archive_mapping = mapping;
    }
    result.monitoring_interval_seconds = configuration.value("monitoring_interval_seconds", 30);
    if (result.monitoring_interval_seconds < 5 || result.monitoring_interval_seconds > 3600) {
        throw std::invalid_argument("monitoring_interval_seconds is outside the safe range");
    }
    result.monitored_signals = configuration.value("monitored_signals", std::vector<std::string>{});
    result.thresholds = configuration.value("thresholds", nlohmann::json::object());
    if (!result.thresholds.is_object()) {
        throw std::invalid_argument("thresholds must be an object");
    }
    const std::set<std::string> threshold_fields{"minimum", "maximum", "max_rate_per_second"};
    for (const auto& [signal_id, thresholds] : result.thresholds.items()) {
        if (signal_id.empty() || !thresholds.is_object()) {
            throw std::invalid_argument("threshold entry must identify a signal and be an object");
        }
        for (const auto& [field, number] : thresholds.items()) {
            if (!threshold_fields.contains(field) || (!number.is_number() && !number.is_null())) {
                throw std::invalid_argument("threshold contains an unsupported field");
            }
        }
    }
    const auto server_url = configuration.value("server_url", std::string{});
    if (!server_url.empty() && !server_url.starts_with("https://")) {
        throw std::invalid_argument("central configuration server_url must use HTTPS");
    }
    if (!server_url.empty()) {
        result.server_url = server_url;
    }
    if (configuration.contains("rescan_requested_at") &&
        !configuration.at("rescan_requested_at").is_null()) {
        result.rescan_requested_at = configuration.at("rescan_requested_at").get<std::string>();
    }
    result.raw = value;
    return result;
}

std::string desired_configuration_hash(const nlohmann::json& configuration) {
    const auto canonical = configuration.dump();
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context) {
        throw std::runtime_error("cannot allocate SHA-256 context");
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size{};
    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), canonical.data(), canonical.size()) != 1 ||
        EVP_DigestFinal_ex(context.get(), digest.data(), &size) != 1) {
        throw std::runtime_error("cannot calculate desired configuration SHA-256");
    }
    std::ostringstream output;
    output << "sha256-" << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < size; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    return output.str();
}

} // namespace scadaguard
