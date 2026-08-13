#pragma once

#include "scadaguard/model.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace scadaguard {

struct IncidentPolicy {
    std::chrono::seconds open_delay{0};
    std::chrono::seconds close_delay{0};
    std::chrono::seconds notification_cooldown{300};
};
struct IncidentEvent {
    std::string type;
    Incident incident;
    TimePoint occurred_at;
};

class IncidentManager {
  public:
    IncidentManager(std::string site_id, std::string host_id, IncidentPolicy policy = {});
    IncidentManager(std::string site_id, std::string host_id, IncidentPolicy policy,
                    std::vector<Incident> restored_incidents);
    std::vector<IncidentEvent> process(const CheckResult& result, TimePoint now);
    std::vector<Incident> incidents() const;
    std::vector<Incident> active_incidents() const;

  private:
    struct Tracked {
        Incident incident;
        TimePoint first_problem{};
        TimePoint last_problem{};
        std::optional<TimePoint> recovery_since;
        TimePoint last_notified{};
        std::uint64_t occurrences{};
    };
    std::string key_for(const CheckResult& result) const;
    static std::string source_for(const CheckResult& result);
    std::string site_id_, host_id_;
    IncidentPolicy policy_;
    std::map<std::string, Tracked> tracked_;
};

} // namespace scadaguard
