#include <shadow/observability/log.hpp>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <atomic>

namespace shadow::observability {
namespace {
std::mutex output_mutex;
std::atomic<std::uint64_t> suppressed_total{0};
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
    // Bound process-wide log amplification. write_log remains an unthrottled
    // formatter for explicit sinks/tests; runtime events never contain payloads.
    static std::mutex limiter_mutex;
    static auto previous = std::chrono::steady_clock::now();
    static double tokens = 400;
    static std::size_t suppressed = 0;
    std::size_t dropped = 0;
    {
        std::lock_guard lock(limiter_mutex);
        const auto now = std::chrono::steady_clock::now();
        tokens = std::min(400.0, tokens + std::chrono::duration<double>(now - previous).count() * 200);
        previous = now;
        if (tokens < 1) { ++suppressed; suppressed_total.fetch_add(1, std::memory_order_relaxed); return; }
        --tokens; dropped = suppressed; suppressed = 0;
    }
    if (dropped != 0) write_log(std::clog, Level::warning, "logging", "events_suppressed count=" + std::to_string(dropped));
    write_log(std::clog, level, component, event);
}
std::uint64_t suppressed_events() { return suppressed_total.load(std::memory_order_relaxed); }
} // namespace shadow::observability
