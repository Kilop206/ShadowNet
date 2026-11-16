#include <shadow/observability/metrics.hpp>
#include <shadow/observability/log.hpp>
#include <shadow/core/error.hpp>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <locale>
#include <sstream>

namespace shadow::observability {
namespace {
constexpr std::array<double, 11> bounds{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10};
constexpr std::array<std::string_view, 7> closure_names{"closed", "authentication", "protocol", "heartbeat", "credentials", "write", "other"};
std::size_t closure(std::string_view reason) {
    if (reason == "tunnel_closed" || reason == "shutdown") return 0;
    if (reason == "tls_handshake_failed" || reason == "agent_not_authorized" || reason == "peer_verification_failed" || reason == "duplicate_agent_session") return 1;
    if (reason == "invalid_tunnel_message" || reason == "websocket_upgrade_rejected") return 2;
    if (reason == "heartbeat_timeout") return 3;
    if (reason == "credential_validation_failed") return 4;
    if (reason == "tunnel_write_timeout" || reason == "tunnel_write_failed" || reason == "write_queue_limit") return 5;
    return 6;
}
}
Metrics::Metrics(Role role, const std::vector<std::string>& agents) : role_(role) {
    if (agents.size() > 1024) throw Error("too many metric agent identities");
    for (const auto& name : agents) {
        if (name.empty() || name.size() > 64) throw Error("invalid metric agent identity");
        for (char c : name) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
            throw Error("invalid metric agent identity");
        if (!agents_.emplace(name, false).second) throw Error("duplicate metric agent identity");
    }
}
void Metrics::http_started() { std::lock_guard lock(mutex_); ++http_total_; ++http_active_; }
void Metrics::http_finished(const HttpResult& result) {
    auto [status, seconds, request_bytes, response_bytes] = result;
    std::lock_guard lock(mutex_);
    if (http_active_ == 0) return;
    --http_active_;
    if (status >= 200 && status <= 599) { ++http_completed_; ++statuses_[status / 100 - 2]; }
    else ++http_aborted_;
    request_bytes_ += request_bytes; response_bytes_ += response_bytes;
    if (!std::isfinite(seconds) || seconds < 0) seconds = 0;
    ++duration_count_; duration_sum_ += seconds;
    for (std::size_t i = 0; i < bounds.size(); ++i) if (seconds <= bounds[i]) ++buckets_[i];
}
void Metrics::tunnel_started() { std::lock_guard lock(mutex_); ++tunnel_total_; ++tunnel_connections_; }
void Metrics::tunnel_up(std::string_view name) {
    std::lock_guard lock(mutex_); ++tunnels_;
    if (const auto found = agents_.find(name); found != agents_.end()) found->second = true;
}
void Metrics::tunnel_finished(const TunnelEnd& result) {
    const auto& [active, name, reason] = result;
    std::lock_guard lock(mutex_);
    if (tunnel_connections_ != 0) --tunnel_connections_;
    if (active) {
        if (tunnels_ != 0) --tunnels_;
        if (const auto found = agents_.find(name); found != agents_.end()) found->second = false;
    }
    ++closures_[closure(reason)];
}
void Metrics::tunnel_bytes(bool sent, std::size_t bytes) {
    std::lock_guard lock(mutex_); const auto index = sent ? 0U : 1U;
    bytes_[index] += bytes; ++messages_[index];
}
void Metrics::https_connection(bool opened) {
    std::lock_guard lock(mutex_);
    if (opened) { ++https_total_; ++https_active_; }
    else if (https_active_ != 0) --https_active_;
}
void Metrics::budget(Budget scope, std::size_t used, std::size_t peak, std::size_t capacity) {
    std::lock_guard lock(mutex_); budgets_[static_cast<std::size_t>(scope)] = {used, peak, capacity};
}
void Metrics::event(Event event) {
    std::lock_guard lock(mutex_);
    const auto index = static_cast<std::size_t>(event);
    if (index < events_.size()) ++events_[index];
}
void Metrics::routes(std::size_t count) { std::lock_guard lock(mutex_); routes_ = count; }
void Metrics::scrape() { std::lock_guard lock(mutex_); ++scrapes_; }
std::string Metrics::render() const {
    std::lock_guard lock(mutex_);
    std::ostringstream out; out.imbue(std::locale::classic()); out << std::setprecision(12);
    const auto metric = [&](std::string_view name, std::string_view type, std::string_view help, auto value) {
        out << "# HELP shadownet_" << name << ' ' << help << "\n# TYPE shadownet_" << name << ' ' << type << "\nshadownet_" << name << ' ' << value << '\n';
    };
    out << "# HELP shadownet_build_info Build version and process role.\n# TYPE shadownet_build_info gauge\nshadownet_build_info{version=\"" << version
        << "\",role=\"" << (role_ == Role::gateway ? "gateway" : "agent") << "\"} 1\n";
    metric("uptime_seconds", "gauge", "Monotonic process runtime.", std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count());
    metric("http_requests_total", "counter", "Started HTTP exchanges, excluding metrics scrapes.", http_total_);
    metric("http_in_flight", "gauge", "Started HTTP exchanges not yet completed or aborted.", http_active_);
    metric("http_completed_total", "counter", "Completed HTTP exchanges.", http_completed_);
    metric("http_aborted_total", "counter", "HTTP exchanges aborted before completion.", http_aborted_);
    metric("http_request_body_bytes_total", "counter", "Bytes of fully received HTTP request bodies.", request_bytes_);
    metric("http_response_body_bytes_total", "counter", "Body bytes of completed HTTP responses.", response_bytes_);
    out << "# HELP shadownet_http_responses_total Completed responses by bounded status class.\n# TYPE shadownet_http_responses_total counter\n";
    for (std::size_t i = 0; i < statuses_.size(); ++i) out << "shadownet_http_responses_total{status_class=\"" << i + 2 << "xx\"} " << statuses_[i] << '\n';
    out << "# HELP shadownet_http_request_duration_seconds Time to completion or abort, excluding TLS shutdown.\n# TYPE shadownet_http_request_duration_seconds histogram\n";
    for (std::size_t i = 0; i < bounds.size(); ++i) out << "shadownet_http_request_duration_seconds_bucket{le=\"" << bounds[i] << "\"} " << buckets_[i] << '\n';
    out << "shadownet_http_request_duration_seconds_bucket{le=\"+Inf\"} " << duration_count_ << "\nshadownet_http_request_duration_seconds_sum " << duration_sum_
        << "\nshadownet_http_request_duration_seconds_count " << duration_count_ << '\n';
    metric("tunnel_connections_total", "counter", "Created tunnel connection attempts after admission.", tunnel_total_);
    metric("tunnel_connections_active", "gauge", "Tunnel connections including handshakes.", tunnel_connections_);
    metric("tunnels_active", "gauge", "Authenticated WSS tunnels.", tunnels_);
    metric("https_connections_total", "counter", "Admitted public HTTPS connections.", https_total_);
    metric("https_connections_active", "gauge", "Public HTTPS connections including TLS and shutdown.", https_active_);
    metric("routes_active", "gauge", "Registered authorized hostname routes.", routes_);
    out << "# HELP shadownet_agent_up Authenticated configured agent identity.\n# TYPE shadownet_agent_up gauge\n";
    for (const auto& [name, up] : agents_) out << "shadownet_agent_up{agent=\"" << name << "\"} " << (up ? 1 : 0) << '\n';
    out << "# HELP shadownet_tunnel_bytes_total Payload bytes of successfully completed WSS messages, including v3 header.\n# TYPE shadownet_tunnel_bytes_total counter\n";
    for (std::size_t i = 0; i < bytes_.size(); ++i) out << "shadownet_tunnel_bytes_total{direction=\"" << (i == 0 ? "sent" : "received") << "\"} " << bytes_[i] << '\n';
    out << "# HELP shadownet_tunnel_messages_total Successfully completed WSS messages.\n# TYPE shadownet_tunnel_messages_total counter\n";
    for (std::size_t i = 0; i < messages_.size(); ++i) out << "shadownet_tunnel_messages_total{direction=\"" << (i == 0 ? "sent" : "received") << "\"} " << messages_[i] << '\n';
    out << "# HELP shadownet_tunnel_closures_total Tunnel closures by fixed category.\n# TYPE shadownet_tunnel_closures_total counter\n";
    for (std::size_t i = 0; i < closures_.size(); ++i) out << "shadownet_tunnel_closures_total{reason=\"" << closure_names[i] << "\"} " << closures_[i] << '\n';
    constexpr std::array<std::string_view, 3> budget_names{"used", "peak", "capacity"};
    for (std::size_t j = 0; j < budget_names.size(); ++j) {
        out << "# HELP shadownet_buffer_" << budget_names[j] << "_bytes Buffer admission reservations, not RSS.\n# TYPE shadownet_buffer_" << budget_names[j] << "_bytes gauge\n";
        for (std::size_t i = 0; i < budgets_.size(); ++i) out << "shadownet_buffer_" << budget_names[j] << "_bytes{scope=\"" << (i == 0 ? "http" : "tunnel") << "\"} " << budgets_[i][j] << '\n';
    }
    constexpr std::array<std::string_view, 5> events{"connection_limit", "buffer_limit", "backpressure", "reconnect", "in_flight_limit"};
    out << "# HELP shadownet_events_total Operational events by fixed category.\n# TYPE shadownet_events_total counter\n";
    for (std::size_t i = 0; i < events.size(); ++i) out << "shadownet_events_total{event=\"" << events[i] << "\"} " << events_[i] << '\n';
    metric("metrics_scrapes_total", "counter", "Valid GET or HEAD metrics requests accepted.", scrapes_);
    metric("log_events_suppressed_total", "counter", "Runtime log events suppressed by the process limiter.", suppressed_events());
    return out.str();
}
HttpObservation::HttpObservation(std::shared_ptr<Metrics> metrics) : metrics_(std::move(metrics)) { if (metrics_) metrics_->http_started(); }
HttpObservation::~HttpObservation() { finish(0, 0); }
void HttpObservation::request_bytes(std::size_t bytes) { request_bytes_ = bytes; }
void HttpObservation::finish(unsigned status, std::size_t response_bytes) {
    if (finished_) return;
    finished_ = true;
    if (metrics_) metrics_->http_finished({status, std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count(), request_bytes_, response_bytes});
}
} // namespace shadow::observability
