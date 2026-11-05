#include <shadow/observability/log.hpp>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>

namespace shadow::observability {
namespace {
std::mutex output_mutex;
std::string sanitize(std::string_view input) {
    std::string result;
    for (char c : input.substr(0, 512)) {
        const auto byte = static_cast<unsigned char>(c);
        result += (byte < 32 || byte >= 127) ? '?' : c;
    }
    return result;
}
}
void write_log(std::ostream& output, Level level, std::string_view component, std::string_view event) {
    const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const char* label = level == Level::info ? "INFO" : level == Level::warning ? "WARN" : "ERROR";
    std::lock_guard lock(output_mutex);
    output << "ts_ms=" << timestamp << " level=" << label << " component=" << sanitize(component)
           << " event=" << sanitize(event) << '\n' << std::flush;
}
void log(Level level, std::string_view component, std::string_view event) {
    write_log(std::clog, level, component, event);
}
} // namespace shadow::observability
