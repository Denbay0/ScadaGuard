#include "scadaguard/environment.hpp"

#include <cstdlib>
#include <memory>

namespace scadaguard {

std::optional<std::string> environment_variable(const std::string_view name) {
    const std::string owned_name(name);
    char* raw_value = nullptr;
    std::size_t size = 0;
    if (_dupenv_s(&raw_value, &size, owned_name.c_str()) != 0) {
        return std::nullopt;
    }
    const std::unique_ptr<char, decltype(&std::free)> value(raw_value, &std::free);
    if (!value || size <= 1) {
        return std::nullopt;
    }
    return std::string(value.get(), size - 1);
}

} // namespace scadaguard
