#pragma once

#include "scadaguard/config.hpp"
#include "scadaguard/model.hpp"

#include <map>
#include <vector>

namespace scadaguard {

class DataQualityAnalyzer {
  public:
    std::vector<CheckResult> analyze(const std::vector<SignalSample>& samples,
                                     const std::vector<SignalRule>& rules, TimePoint now);
    std::vector<CheckResult> compare_archive(const std::vector<SignalSample>& current,
                                             const std::vector<SignalSample>& archive,
                                             const std::vector<SignalRule>& rules,
                                             TimePoint now) const;
    void restore_history(const std::vector<SignalSample>& samples);
    void reset();

  private:
    struct History {
        SignalSample previous;
        TimePoint stable_since;
        bool initialized{};
    };
    std::map<std::string, History> history_;
};

} // namespace scadaguard
