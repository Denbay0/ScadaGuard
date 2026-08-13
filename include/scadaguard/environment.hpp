#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace scadaguard {

std::optional<std::string> environment_variable(std::string_view name);

} // namespace scadaguard
