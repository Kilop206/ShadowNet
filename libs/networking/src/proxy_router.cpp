#include "proxy_router.hpp"
#include <shadow/core/error.hpp>
#include <shadow/observability/log.hpp>
#include <algorithm>
#include <limits>

namespace shadow::networking::detail {
namespace px = protocol::proxy;
namespace wire = protocol::tunnel;
using Code = boost::system::error_code;
using observability::Level;
using observability::log;

GatewayProxy::GatewayProxy(boost::asio::io_context& context, configuration::Gateway config)
    : context_(context), config_(std::move(config)), limits_(config_.http.value_or(configuration::Https{})), tokens_(limits_.requests_per_second) {
    for (const auto& agent : config_.authorized_agents) for (const auto& service : agent.services) authorized_hosts_.insert(service.hostname);
}
bool GatewayProxy::message(const std::shared_ptr<SecureSession>& session, const wire::Frame& frame) {
    if (stopped_) return false;
    if (frame.type == wire::Type::register_services) {
        if (registered_.contains(session.get())) return false;
        const auto services = px::decode_services(frame.payload);
        const auto agent = std::find_if(config_.authorized_agents.begin(), config_.authorized_agents.end(),
            [&](const auto& value) { return value.name == session->name(); });
        if (agent == config_.authorized_agents.end()) return false;
        for (const auto& service : services) {
            const auto allowed = std::find_if(agent->services.begin(), agent->services.end(), [&](const auto& entry) {
                return entry.name == service.name && entry.hostname == service.hostname;
            });
            if (allowed == agent->services.end() || routes_.contains(service.hostname)) return false;
        }
        if (!session->transmit({wire::Type::registered, frame.payload})) return false;
        registered_.insert(session.get());
        for (const auto& service : services) routes_.emplace(service.hostname, Route{service.name, session});
        log(Level::info, "gateway", "services_registered count=" + std::to_string(services.size()));
        return true;
    }
    if (frame.type != wire::Type::response || !registered_.contains(session.get())) return false;
    auto response = px::decode_response(frame.payload);
    const auto found = pending_.find(response.id);
    if (found == pending_.end()) return true; // A timed-out response must never match a new request.
    if (found->second.session.lock() != session || (found->second.head && !response.body.empty())) return false;
    if (!found->second.head && response.status != 304 && !px::single_field(response.fields, "content-length").empty()) return false;
    const auto id = response.id;
    complete(id, std::move(response));
    return true;
}
CancelRequest GatewayProxy::dispatch(px::Request request, ProxyCompletion done) {
    if (stopped_) { done(px::error_response(0, 503)); return {}; }
    const auto now = std::chrono::steady_clock::now();
    tokens_ = std::min(static_cast<double>(limits_.requests_per_second), tokens_ +
        std::chrono::duration<double>(now - refill_).count() * limits_.requests_per_second);
    refill_ = now;
    if (tokens_ < 1) { done(px::error_response(0, 429)); return {}; }
    tokens_ -= 1;
    const auto host = px::hostname(px::single_field(request.fields, "host"));
    if (!authorized_hosts_.contains(host)) { done(px::error_response(0, 404)); return {}; }
    const auto route = routes_.find(host);
    if (route == routes_.end()) { done(px::error_response(0, 503)); return {}; }
    const auto session = route->second.session.lock();
    if (!session || pending_.size() >= limits_.max_in_flight || next_id_ == std::numeric_limits<std::uint64_t>::max()) {
        done(px::error_response(0, 503)); return {};
    }
    request.id = ++next_id_;
    request.service = route->second.service;
    const auto id = request.id;
    const auto payload = px::encode_request(request);
    auto timer = std::make_shared<boost::asio::steady_timer>(context_);
    pending_.emplace(id, Pending{session, std::move(done), timer, request.method == "HEAD"});
    if (!session->transmit({wire::Type::request, payload})) { complete(id, px::error_response(id, 503)); return {}; }
    timer->expires_after(limits_.timeout);
    timer->async_wait([owner = weak_from_this(), id](Code error) {
        if (!error) if (const auto router = owner.lock()) {
            const auto found = router->pending_.find(id);
            if (found == router->pending_.end()) return;
            if (const auto connection = found->second.session.lock()) (void)connection->transmit({wire::Type::cancel, px::encode_id(id)});
            router->complete(id, px::error_response(id, 504));
        }
    });
    return [owner = weak_from_this(), id] { if (const auto router = owner.lock()) router->cancel(id); };
}
void GatewayProxy::complete(std::uint64_t id, px::Response response) {
    const auto found = pending_.find(id);
    if (found == pending_.end()) return;
    auto pending = std::move(found->second);
    pending_.erase(found);
    pending.timer->cancel();
    pending.done(std::move(response));
}
void GatewayProxy::cancel(std::uint64_t id) {
    const auto found = pending_.find(id);
    if (found == pending_.end()) return;
    if (const auto session = found->second.session.lock()) (void)session->transmit({wire::Type::cancel, px::encode_id(id)});
    found->second.timer->cancel();
    pending_.erase(found);
}
void GatewayProxy::disconnected(const std::shared_ptr<SecureSession>& session) {
    registered_.erase(session.get());
    std::erase_if(routes_, [&](const auto& entry) { return entry.second.session.lock() == session; });
    std::vector<std::uint64_t> failed;
    for (const auto& [id, pending] : pending_) if (pending.session.lock() == session) failed.push_back(id);
    for (const auto id : failed) complete(id, px::error_response(id, 503));
}
void GatewayProxy::stop() {
    if (stopped_) return;
    stopped_ = true;
    routes_.clear();
    std::vector<std::uint64_t> failed;
    for (const auto& [id, pending] : pending_) { (void)pending; failed.push_back(id); }
    for (const auto id : failed) complete(id, px::error_response(id, 503));
}
AgentProxy::AgentProxy(boost::asio::io_context& context, configuration::Agent config, Send send, std::shared_ptr<BufferBudget> budget)
    : context_(context), config_(std::move(config)), send_(std::move(send)), budget_(std::move(budget)) {
    for (const auto& service : config_.services) services_.push_back({service.name, service.hostname});
}
void AgentProxy::start() {
    if (services_.empty()) registered_ = true;
    else if (!send_({wire::Type::register_services, px::encode_services(services_)})) stop();
}
bool AgentProxy::message(const wire::Frame& frame) {
    if (stopped_) return false;
    if (frame.type == wire::Type::registered) {
        if (registered_ || px::decode_services(frame.payload) != services_) return false;
        registered_ = true;
        log(Level::info, "agent", "services_registered count=" + std::to_string(services_.size()));
        return true;
    }
    if (!registered_) return false;
    if (frame.type == wire::Type::cancel) {
        const auto id = px::decode_id(frame.payload);
        if (const auto found = requests_.find(id); found != requests_.end()) {
            if (found->second.response) log(Level::info, "agent", "response_cancelled id=" + std::to_string(id));
            auto local = found->second.local;
            requests_.erase(found); std::erase(responses_, id);
            if (local) local->cancel();
        }
        return true;
    }
    if (frame.type != wire::Type::request) return false;
    auto request = px::decode_request(frame.payload);
    if (request.id <= last_id_) return false;
    last_id_ = request.id;
    // A conforming gateway has at most 64 pending requests. A small bounded
    // allowance for rejected requests keeps hostile peers from growing replies.
    if (requests_.size() >= 128) return false;
    const auto service = std::find_if(config_.services.begin(), config_.services.end(), [&](const auto& value) { return value.name == request.service; });
    const auto reply = [&](unsigned status) {
        auto response = px::error_response(request.id, status);
        if (request.method == "HEAD") {
            response.fields.emplace_back("content-length", std::to_string(response.body.size()));
            response.body.clear();
        }
        requests_.emplace(request.id, Work{{}, {}, wire::Frame{wire::Type::response, px::encode_response(response)}});
        responses_.push_back(request.id);
        writable();
        return true;
    };
    if (service == config_.services.end()) return reply(404);
    if (px::hostname(px::single_field(request.fields, "host")) != service->hostname) return reply(403);
    if (requests_.size() >= config_.max_in_flight) return reply(503);
    auto reservation = budget_->acquire(4 * wire::max_message);
    if (!reservation) return reply(503);
    const auto id = request.id;
    auto local = std::make_shared<LocalHttp>(context_, *service, std::move(request), config_.backend_timeout,
        [owner = weak_from_this(), id](const px::Response& response) {
            if (const auto agent = owner.lock(); agent && !agent->stopped_) {
                const auto found = agent->requests_.find(id);
                if (found == agent->requests_.end()) return;
                found->second.local.reset();
                found->second.response = wire::Frame{wire::Type::response, px::encode_response(response)};
                agent->responses_.push_back(id);
                agent->writable();
            }
        }, reservation);
    requests_.emplace(id, Work{local, std::move(reservation), {}});
    local->start();
    return true;
}
void AgentProxy::writable() {
    if (stopped_) return;
    while (!responses_.empty()) {
        const auto id = responses_.front();
        const auto found = requests_.find(id);
        if (found == requests_.end()) { responses_.pop_front(); continue; }
        auto& response = found->second.response;
        if (!response) { responses_.pop_front(); continue; }
        if (!send_(*response)) {
            if (!backpressured_) log(Level::info, "agent", "response_backpressure id=" + std::to_string(id));
            backpressured_ = true;
            return;
        }
        responses_.pop_front(); requests_.erase(found);
    }
    if (backpressured_) log(Level::info, "agent", "response_resumed");
    backpressured_ = false;
}
void AgentProxy::stop() {
    if (stopped_) return;
    stopped_ = true;
    auto requests = std::move(requests_);
    responses_.clear();
    for (const auto& [id, work] : requests) { (void)id; if (work.local) work.local->cancel(); }
}
} // namespace shadow::networking::detail
