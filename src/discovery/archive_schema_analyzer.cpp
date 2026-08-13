#include "scadaguard/discovery.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <ranges>
#include <set>
#include <string_view>

namespace scadaguard {
namespace {

std::string lowercase(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

bool contains_any(const std::string& value, const std::initializer_list<std::string_view> tokens) {
    const auto normalized = lowercase(value);
    return std::ranges::any_of(
        tokens, [&](const auto token) { return normalized.find(token) != std::string::npos; });
}

bool numeric_type(const std::string& type) {
    return contains_any(type, {"int", "real", "float", "double", "numeric", "decimal"});
}

bool text_type(const std::string& type) {
    return contains_any(type, {"char", "text", "clob"});
}

bool indexed_column(const SqliteObjectMetadata& object, const std::string& column) {
    return std::ranges::any_of(object.indexes, [&](const auto& index) {
        return std::ranges::find(index.columns, column) != index.columns.end();
    });
}

int sample_score(const SqliteObjectMetadata& object, const std::string& column,
                 const std::string_view role) {
    int score = 0;
    std::set<std::string> distinct;
    std::size_t populated = 0;
    for (const auto& row : object.recent_samples) {
        if (!row.is_object() || !row.contains(column) || row.at(column).is_null()) {
            continue;
        }
        ++populated;
        const auto& value = row.at(column);
        distinct.insert(value.dump());
        if (role == "timestamp") {
            if (value.is_number_integer() || value.is_number_float()) {
                score += 2;
            } else if (value.is_string() &&
                       contains_any(value.get<std::string>(), {"-", ":", "t", "z"})) {
                score += 3;
            }
        } else if (role == "value" && (value.is_number() || value.is_boolean())) {
            score += 2;
        }
    }
    if (populated >= 2) {
        score += 2;
    }
    if (role == "signal_id" && populated >= 2 && distinct.size() <= populated) {
        score += 1;
    }
    return std::min(score, 10);
}

int role_score(const SqliteObjectMetadata& object, const SqliteObjectMetadata::Column& column,
               const std::string_view role) {
    int score = sample_score(object, column.name, role);
    if (indexed_column(object, column.name)) {
        score += role == "value" ? 1 : 4;
    }
    if (role == "timestamp") {
        if (contains_any(column.name, {"timestamp", "datetime", "date_time", "time", "stamp"})) {
            score += 15;
        }
        if (contains_any(column.declared_type, {"date", "time"}) ||
            numeric_type(column.declared_type)) {
            score += 4;
        }
    } else if (role == "signal_id") {
        if (contains_any(column.name, {"signal", "item", "tag", "point", "parameter", "param"})) {
            score += 12;
        }
        if (contains_any(column.name, {"id", "key", "guid", "uuid"})) {
            score += 7;
        }
        if (text_type(column.declared_type) || numeric_type(column.declared_type)) {
            score += 3;
        }
        if (column.primary_key || std::ranges::any_of(object.foreign_keys, [&](const auto& key) {
                return key.from_column == column.name;
            })) {
            score += 4;
        }
    } else if (role == "value") {
        if (contains_any(column.name, {"value", "val", "reading", "measurement", "data"})) {
            score += 15;
        }
        if (numeric_type(column.declared_type)) {
            score += 7;
        }
    } else if (role == "quality") {
        if (contains_any(column.name, {"quality", "status", "state", "valid"})) {
            score += 15;
        }
        if (numeric_type(column.declared_type) || text_type(column.declared_type)) {
            score += 3;
        }
    }
    return score;
}

std::optional<std::string> best_column(const SqliteObjectMetadata& object,
                                       const std::string_view role, const int threshold,
                                       int& best_score) {
    std::optional<std::string> result;
    best_score = 0;
    for (const auto& column : object.column_metadata) {
        const auto score = role_score(object, column, role);
        if (score > best_score) {
            best_score = score;
            result = column.name;
        }
    }
    if (best_score < threshold) {
        return std::nullopt;
    }
    return result;
}

} // namespace

std::vector<ArchiveSchemaCandidate>
ArchiveSchemaAnalyzer::analyze(const SqliteInspection& inspection) {
    std::vector<ArchiveSchemaCandidate> result;
    for (const auto& object : inspection.objects) {
        if (object.type != "table" || object.column_metadata.empty()) {
            continue;
        }
        int timestamp_score = 0;
        int signal_score = 0;
        int value_score = 0;
        int quality_score = 0;
        ArchiveSchemaCandidate candidate;
        candidate.table = object.name;
        candidate.roles.timestamp = best_column(object, "timestamp", 10, timestamp_score);
        candidate.roles.signal_id = best_column(object, "signal_id", 10, signal_score);
        candidate.roles.value = best_column(object, "value", 10, value_score);
        candidate.roles.quality = best_column(object, "quality", 12, quality_score);

        if (candidate.roles.timestamp) {
            candidate.evidence.push_back(
                "timestamp candidate inferred from name, type, samples, and indexes");
        }
        if (candidate.roles.signal_id) {
            candidate.evidence.push_back(
                "signal identifier candidate inferred from metadata relationships");
        }
        if (candidate.roles.value) {
            candidate.evidence.push_back(
                "value candidate inferred from name, type, and bounded samples");
        }
        if (!object.foreign_keys.empty()) {
            candidate.evidence.push_back("table has metadata relationships through foreign keys");
        }
        if (object.bounded_row_count) {
            candidate.evidence.push_back(
                object.row_count_limit_reached
                    ? "row count exceeds bounded inspection limit"
                    : "row count obtained by bounded read-only inspection");
        }

        const auto complete_roles = static_cast<int>(candidate.roles.timestamp.has_value()) +
                                    static_cast<int>(candidate.roles.signal_id.has_value()) +
                                    static_cast<int>(candidate.roles.value.has_value());
        const auto total_score = timestamp_score + signal_score + value_score;
        if (complete_roles == 3 && total_score >= 55) {
            candidate.confidence = DiscoveryConfidence::High;
        } else if (complete_roles >= 2 && total_score >= 30) {
            candidate.confidence = DiscoveryConfidence::Medium;
        } else if (complete_roles >= 1) {
            candidate.confidence = DiscoveryConfidence::Low;
        } else {
            continue;
        }
        candidate.needs_confirmation = true;
        result.push_back(std::move(candidate));
    }
    std::ranges::sort(result, [](const auto& left, const auto& right) {
        return static_cast<int>(left.confidence) > static_cast<int>(right.confidence);
    });
    return result;
}

} // namespace scadaguard
