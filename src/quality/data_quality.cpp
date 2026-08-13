#include "scadaguard/data_quality.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace scadaguard {
namespace {

CheckResult issue(const SignalSample& s, std::string type, std::string message,
                  nlohmann::json details = {}) {
    details["problem_type"] = type;
    details["signal_id"] = s.signal_id;
    return {"quality." + s.signal_id + "." + type,
            "data-quality",
            HealthStatus::Warning,
            std::move(message),
            Clock::now(),
            std::move(details)};
}
const SignalRule* find_rule(const std::vector<SignalRule>& rules, const std::string& id) {
    const auto it =
        std::find_if(rules.begin(), rules.end(), [&](const auto& r) { return r.signal_id == id; });
    return it == rules.end() ? nullptr : &*it;
}
bool nearly_equal(double a, double b, double abs_tol, double rel_tol) {
    return std::abs(a - b) <= std::max(abs_tol, rel_tol * std::max(std::abs(a), std::abs(b)));
}

} // namespace

std::vector<CheckResult> DataQualityAnalyzer::analyze(const std::vector<SignalSample>& samples,
                                                      const std::vector<SignalRule>& rules,
                                                      const TimePoint now) {
    std::vector<CheckResult> results;
    for (const auto& s : samples) {
        const auto* r = find_rule(rules, s.signal_id);
        if (!r || !r->enabled)
            continue;
        if (now - s.source_timestamp > std::chrono::seconds(r->max_age_seconds))
            results.push_back(
                issue(s, "stale", "Source value is stale",
                      {{"age_seconds",
                        std::chrono::duration_cast<std::chrono::seconds>(now - s.source_timestamp)
                            .count()}}));
        if (std::find(r->allowed_quality.begin(), r->allowed_quality.end(), s.quality) ==
            r->allowed_quality.end())
            results.push_back(
                issue(s, "bad_quality", "Signal quality is not allowed", {{"quality", s.quality}}));
        if ((r->minimum && s.value < *r->minimum) || (r->maximum && s.value > *r->maximum))
            results.push_back(issue(s, "out_of_range", "Signal value is outside configured range",
                                    {{"value", s.value}}));
        if (std::any_of(r->invalid_sentinels.begin(), r->invalid_sentinels.end(),
                        [&](double v) { return v == s.value; }))
            results.push_back(issue(s, "invalid_sentinel",
                                    "Signal contains a configured invalid sentinel",
                                    {{"value", s.value}}));

        auto& h = history_[s.signal_id];
        if (h.initialized) {
            const auto delta = s.source_timestamp - h.previous.source_timestamp;
            if (delta < std::chrono::seconds::zero())
                results.push_back(
                    issue(s, "non_monotonic_timestamp", "Source timestamp moved backwards"));
            if (r->expected_period_seconds &&
                delta > std::chrono::duration<double>(*r->expected_period_seconds *
                                                      r->missing_period_multiplier))
                results.push_back(
                    issue(s, "missing_samples", "Gap between samples exceeds configured period",
                          {{"gap_seconds", std::chrono::duration<double>(delta).count()}}));
            if (delta > std::chrono::seconds::zero() && r->max_rate_per_second) {
                const double rate = std::abs(s.value - h.previous.value) /
                                    std::chrono::duration<double>(delta).count();
                if (rate > *r->max_rate_per_second)
                    results.push_back(issue(s, "excessive_rate",
                                            "Rate of change exceeds configured maximum",
                                            {{"rate_per_second", rate}}));
            }
            if (std::abs(s.value - h.previous.value) > r->frozen_epsilon)
                h.stable_since = s.source_timestamp;
            if (r->frozen_after_seconds && s.source_timestamp - h.stable_since >=
                                               std::chrono::seconds(*r->frozen_after_seconds))
                results.push_back(issue(s, "frozen",
                                        "Signal value has remained within epsilon too long",
                                        {{"epsilon", r->frozen_epsilon}}));
        } else {
            h.stable_since = s.source_timestamp;
            h.initialized = true;
        }
        if (!h.initialized || s.source_timestamp >= h.previous.source_timestamp)
            h.previous = s;
    }
    for (auto& result : results)
        result.observed_at = now;
    return results;
}

std::vector<CheckResult> DataQualityAnalyzer::compare_archive(
    const std::vector<SignalSample>& current, const std::vector<SignalSample>& archive,
    const std::vector<SignalRule>& rules, const TimePoint now) const {
    std::vector<CheckResult> results;
    for (const auto& c : current) {
        const auto* r = find_rule(rules, c.signal_id);
        if (!r || !r->enabled ||
            now - c.source_timestamp < std::chrono::seconds(r->archive_delay_seconds))
            continue;
        const SignalSample* best = nullptr;
        auto best_distance = TimePoint::duration::max();
        for (const auto& a : archive)
            if (a.signal_id == c.signal_id) {
                auto d = a.source_timestamp > c.source_timestamp
                             ? a.source_timestamp - c.source_timestamp
                             : c.source_timestamp - a.source_timestamp;
                if (d < best_distance) {
                    best = &a;
                    best_distance = d;
                }
            }
        if (!best || best_distance > std::chrono::seconds(r->archive_match_window_seconds)) {
            auto value = issue(c, "archive_missing",
                               "No archive sample exists in the configured match window");
            value.observed_at = now;
            results.push_back(std::move(value));
            continue;
        }
        if (!nearly_equal(c.value, best->value, r->archive_absolute_tolerance,
                          r->archive_relative_tolerance)) {
            auto value = issue(c, "archive_mismatch", "Online and archive values differ",
                               {{"online_value", c.value}, {"archive_value", best->value}});
            value.observed_at = now;
            results.push_back(std::move(value));
        }
    }
    return results;
}

void DataQualityAnalyzer::reset() {
    history_.clear();
}

void DataQualityAnalyzer::restore_history(const std::vector<SignalSample>& samples) {
    history_.clear();
    for (const auto& sample : samples) {
        history_[sample.signal_id] = History{sample, sample.source_timestamp, true};
    }
}

} // namespace scadaguard
