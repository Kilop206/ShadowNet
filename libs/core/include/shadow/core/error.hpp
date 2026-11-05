#pragma once
#include <stdexcept>
#include <string>

namespace shadow {
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};
inline constexpr const char* version = SHADOW_VERSION;
} // namespace shadow
