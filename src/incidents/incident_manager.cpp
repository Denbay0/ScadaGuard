#include "scadaguard/incident_manager.hpp"

#include <algorithm>
namespace scadaguard {

IncidentManager::IncidentManager(std::string site_id, std::string host_id, IncidentPolicy policy)
    : site_id_(std::move(site_id)), host_id_(std::move(host_id)), policy_(policy) {}

IncidentManager::IncidentManager(std::string site_id, std::string host_id, IncidentPolicy policy,
                                 std::vector<Incident> restored_incidents)
    : IncidentManager(std::move(site_id), std::move(host_id), policy) {
    for (auto& incident : restored_incidents) {
        Tracked tracked;
        tracked.incident = std::move(incident);
        tracked.first_problem = tracked.incident.active ? tracked.incident.opened_at : TimePoint{};
        tracked.last_problem = tracked.incident.last_seen_at == TimePoint{}
                                   ? tracked.incident.opened_at
                                   : tracked.incident.last_seen_at;
        tracked.last_notified = tracked.last_problem;
        tracked.occurrences = tracked.incident.active ? tracked.incident.occurrence_count : 0;
        tracked_[tracked.incident.incident_key] = std::move(tracked);
    }
}

std::string IncidentManager::key_for(const CheckResult& r) const {
    return site_id_ + "|" + host_id_ + "|" + r.component + "|" + r.check_id + "|" +
           r.details.value("problem_type", std::string("health"));
}

std::string IncidentManager::source_for(const CheckResult& result) {
    if (result.details.contains("source")) {
        return result.details.at("source").get<std::string>();
    }
    if (result.component == "data-quality") {
        return "data_quality";
    }
    if (result.component == "archive") {
        return "archive";
    }
    if (result.component == "opcua") {
        return "opcua";
    }
    if (result.component == "internal") {
        return "system";
    }
    return "agent";
}

std::vector<IncidentEvent> IncidentManager::process(const CheckResult& r, const TimePoint now) {
    std::vector<IncidentEvent> events;
    const auto key = key_for(r);
    auto& t = tracked_[key];
    const bool problem = r.status == HealthStatus::Warning || r.status == HealthStatus::Critical ||
                         r.status == HealthStatus::Unknown;
    if (problem) {
        if (t.first_problem == TimePoint{})
            t.first_problem = now;
        t.last_problem = now;
        t.recovery_since.reset();
        ++t.occurrences;
        if (!t.incident.active && now - t.first_problem >= policy_.open_delay) {
            t.incident = {
                generate_uuid_v4(), key,          r.component, r.status, r.message, r.message,
                t.first_problem,    std::nullopt, true,        r.details};
            t.incident.source = source_for(r);
            t.incident.last_seen_at = now;
            t.incident.occurrence_count = t.occurrences;
            t.incident.details["last_detected_at"] = format_utc(now);
            t.incident.details["occurrences"] = t.occurrences;
            t.incident.last_seen_at = now;
            t.incident.occurrence_count = t.occurrences;
            t.last_notified = now;
            events.push_back({"opened", t.incident, now});
        } else if (t.incident.active) {
            t.incident.severity = r.status;
            t.incident.description = r.message;
            t.incident.details = r.details;
            t.incident.details["last_detected_at"] = format_utc(now);
            t.incident.details["occurrences"] = t.occurrences;
            if (now - t.last_notified >= policy_.notification_cooldown) {
                t.last_notified = now;
                events.push_back({"reminder", t.incident, now});
            }
        }
    } else if (t.incident.active) {
        if (!t.recovery_since)
            t.recovery_since = now;
        if (now - *t.recovery_since >= policy_.close_delay) {
            t.incident.active = false;
            t.incident.closed_at = now;
            t.incident.details["recovered_at"] = format_utc(now);
            events.push_back({"recovered", t.incident, now});
            t.first_problem = {};
        }
    } else if (t.incident.incident_key.empty())
        tracked_.erase(key);
    return events;
}

std::vector<Incident> IncidentManager::incidents() const {
    std::vector<Incident> out;
    for (const auto& [_, v] : tracked_)
        if (!v.incident.incident_key.empty())
            out.push_back(v.incident);
    return out;
}
std::vector<Incident> IncidentManager::active_incidents() const {
    auto out = incidents();
    std::erase_if(out, [](const auto& i) { return !i.active; });
    return out;
}

} // namespace scadaguard
