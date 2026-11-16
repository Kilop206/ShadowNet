#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace shadow::observability {
enum class Role : std::uint8_t { gateway, agent };
enum class Budget : std::uint8_t { http, tunnel };
enum class Event : std::uint8_t { connection_limit, buffer_limit, backpressure, reconnect, in_flight_limit, count };
struct HttpResult { unsigned status; double seconds; std::size_t request_bytes; std::size_t response_bytes; };
struct TunnelEnd { bool active; std::string_view agent; std::string_view reason; };
class Metrics {
public:
    explicit Metrics(Role role, const std::vector<std::string>& agents = {});
    void http_started();
    void http_finished(const HttpResult& result);
    void tunnel_started();
    void tunnel_up(std::string_view name);
    void tunnel_finished(const TunnelEnd& result);
    void tunnel_bytes(bool sent, std::size_t bytes);
    void https_connection(bool opened);
    void budget(Budget scope, std::size_t used, std::size_t peak, std::size_t capacity);
    void event(Event event);
    void routes(std::size_t count);
    void scrape();
    std::string render() const;
private:
    mutable std::mutex mutex_;
    Role role_;
    std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
    std::map<std::string, bool, std::less<>> agents_;
    std::uint64_t http_total_ = 0, http_active_ = 0, http_aborted_ = 0, http_completed_ = 0;
    std::uint64_t request_bytes_ = 0, response_bytes_ = 0, duration_count_ = 0;
    std::array<std::uint64_t, 4> statuses_{};
    std::array<std::uint64_t, 11> buckets_{};
    double duration_sum_ = 0;
    std::uint64_t tunnel_total_ = 0, tunnel_connections_ = 0, tunnels_ = 0, https_total_ = 0, https_active_ = 0;
    std::array<std::uint64_t, 2> bytes_{}, messages_{};
    std::array<std::uint64_t, 7> closures_{};
    std::array<std::array<std::size_t, 3>, 2> budgets_{};
    std::array<std::uint64_t, static_cast<std::size_t>(Event::count)> events_{};
    std::size_t routes_ = 0;
    std::uint64_t scrapes_ = 0;
};
// A logical HTTP exchange ends exactly once, including abort/cancellation.
class HttpObservation {
public:
    explicit HttpObservation(std::shared_ptr<Metrics> metrics);
    ~HttpObservation();
    HttpObservation(const HttpObservation&) = delete;
    HttpObservation& operator=(const HttpObservation&) = delete;
    void request_bytes(std::size_t bytes);
    void finish(unsigned status, std::size_t response_bytes);
private:
    std::shared_ptr<Metrics> metrics_;
    std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
    std::size_t request_bytes_ = 0;
    bool finished_ = false;
};
} // namespace shadow::observability
