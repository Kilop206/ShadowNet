#pragma once
#include <string_view>

namespace shadow::security {
bool is_loopback(std::string_view value) noexcept;
bool valid_identifier(std::string_view value) noexcept;
bool valid_hostname(std::string_view value) noexcept;
} // namespace shadow::security
