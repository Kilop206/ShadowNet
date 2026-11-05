#pragma once
#include <cstdint>
#include <iosfwd>
#include <string_view>

namespace shadow::observability {
enum class Level : std::uint8_t { info, warning, error };
// Single-line, bounded output. Never pass credentials or request bodies.
void log(Level level, std::string_view component, std::string_view event);
void write_log(std::ostream& output, Level level, std::string_view component, std::string_view event);
} // namespace shadow::observability
