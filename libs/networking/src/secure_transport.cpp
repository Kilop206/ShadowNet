#include <shadow/networking/secure_transport.hpp>
#include "secure_session.hpp"
#include "proxy_router.hpp"
#include "https_server.hpp"
#include "metrics_server.hpp"
#include <shadow/protocol/outbox.hpp>
#include <shadow/core/error.hpp>
#include <shadow/observability/log.hpp>
#include <shadow/security/tls.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <csignal>
#include <random>
#include <set>
#include <unordered_set>

namespace shadow::networking {
namespace {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using Code = boost::system::error_code;
using detail::SecureSession;
using observability::Level;
using observability::log;
std::shared_ptr<observability::Metrics> gateway_metrics(const configuration::Gateway& config) {
    std::vector<std::string> names;
    names.reserve(config.authorized_agents.size());
    for (const auto& agent : config.authorized_agents) names.push_back(agent.name);
    return std::make_shared<observability::Metrics>(observability::Role::gateway, names);
}

class SecureGateway : public std::enable_shared_from_this<SecureGateway> {
public:
    SecureGateway(asio::io_context& context, const configuration::Gateway& config)
        : context_(context), tls_(security::make_tls_context(config.tls, true)), acceptor_(context), config_(config),
          metrics_(gateway_metrics(config)), proxy_(std::make_shared<detail::GatewayProxy>(context, config, metrics_)), tunnel_budget_(config.tunnel_buffer_budget_bytes) {
        const tcp::endpoint endpoint(asio::ip::make_address(config.bind_host), config.port);
        acceptor_.open(endpoint.protocol());
#ifndef _WIN32
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
#endif
        acceptor_.bind(endpoint);
        acceptor_.listen(static_cast<int>(config.max_connections));
    }
    void start() {
        metrics_->budget(observability::Budget::tunnel, tunnel_budget_.used(), tunnel_budget_.peak(), tunnel_budget_.capacity());
        tunnel_budget_.on_release([owner = weak_from_this()] {
            if (const auto gateway = owner.lock()) gateway->metrics_->budget(observability::Budget::tunnel,
                gateway->tunnel_budget_.used(), gateway->tunnel_budget_.peak(), gateway->tunnel_budget_.capacity());
        });
        if (config_.metrics) {
            exporter_ = std::make_shared<detail::MetricsServer>(context_, *config_.metrics, metrics_);
            exporter_->start();
        }
        if (config_.http) {
            http_ = std::make_shared<detail::HttpsServer>(context_, *config_.http,
                [owner = std::weak_ptr<detail::GatewayProxy>(proxy_)](protocol::proxy::Request request, detail::ProxyCompletion done) {
                    if (const auto router = owner.lock()) return router->dispatch(std::move(request), std::move(done));
                    done(protocol::proxy::error_response(0, 503));
                    return detail::CancelRequest{};
                }, metrics_);
            http_->start();
        }
        log(Level::info, "gateway", "wss_listening port=" + std::to_string(config_.port));
        accept();
    }
    void stop() {
        if (stopping_) return;
        stopping_ = true;
        if (exporter_) exporter_->stop();
        if (http_) http_->stop();
        proxy_->stop();
        Code ignored;
        acceptor_.close(ignored);
        const auto sessions = sessions_;
        for (const auto& session : sessions) session->stop();
        log(Level::info, "gateway", "shutdown_started");
    }
private:
    void accept() {
        acceptor_.async_accept([self = shared_from_this()](Code error, tcp::socket socket) {
            if (self->stopping_) return;
            if (error) throw Error("secure gateway accept failed");
            if (self->sessions_.size() >= self->config_.max_connections) {
                self->metrics_->event(observability::Event::connection_limit);
                Code ignored; socket.close(ignored);
                log(Level::warning, "gateway", "connection_limit_reached");
            } else if (auto reservation = self->tunnel_budget_.acquire(protocol::tunnel::Outbox::session_reservation)) {
                self->metrics_->budget(observability::Budget::tunnel, self->tunnel_budget_.used(), self->tunnel_budget_.peak(), self->tunnel_budget_.capacity());
                self->session(std::move(socket), std::move(reservation));
            } else {
                self->metrics_->event(observability::Event::buffer_limit);
                Code ignored; socket.close(ignored);
                log(Level::warning, "gateway", "tunnel_buffer_limit");
            }
            self->accept();
        });
    }
    void session(tcp::socket socket, std::shared_ptr<BufferBudget::Lease> reservation) {
        const auto owner = std::weak_ptr<SecureGateway>(shared_from_this());
        auto holder = std::make_shared<std::weak_ptr<SecureSession>>();
        detail::SessionOptions options;
        options.server = true;
        options.timeout = config_.timeout;
        options.interval = config_.heartbeat_interval;
        options.pong_timeout = config_.heartbeat_timeout;
        options.write_timeout = config_.write_timeout;
        options.reservation = std::move(reservation);
        options.metrics = metrics_;
        options.authorize = [owner](const std::string& fingerprint) {
            if (const auto gateway = owner.lock()) {
                for (const auto& agent : gateway->config_.authorized_agents)
                    if (agent.certificate_sha256 == fingerprint || agent.certificate_sha256_next == fingerprint) return agent.name;
            }
            return std::string{};
        };
        options.claim = [owner](const std::string& name) {
            const auto gateway = owner.lock();
            return gateway && !gateway->stopping_ && gateway->names_.insert(name).second;
        };
        options.message = [owner, holder](const protocol::tunnel::Frame& frame) {
            const auto gateway = owner.lock(); const auto session = holder->lock();
            return gateway && session && gateway->proxy_->message(session, frame);
        };
        options.done = [owner, holder](const std::string& reason) {
            if (auto gateway = owner.lock()) {
                if (auto session = holder->lock()) {
                    gateway->proxy_->disconnected(session);
                    if (session->claimed()) gateway->names_.erase(session->name());
                    gateway->sessions_.erase(session);
                }
                log(Level::info, "gateway", reason);
            }
        };
        auto session = std::make_shared<SecureSession>(std::move(socket), tls_, std::move(options));
        *holder = session;
        sessions_.insert(session);
        session->accept();
    }
    asio::io_context& context_;
    std::shared_ptr<asio::ssl::context> tls_;
    tcp::acceptor acceptor_;
    configuration::Gateway config_;
    std::shared_ptr<observability::Metrics> metrics_;
    std::shared_ptr<detail::MetricsServer> exporter_;
    std::shared_ptr<detail::GatewayProxy> proxy_;
    std::shared_ptr<detail::HttpsServer> http_;
    BufferBudget tunnel_budget_;
    std::unordered_set<std::shared_ptr<SecureSession>> sessions_;
    std::set<std::string> names_;
    bool stopping_ = false;
};

class SecureAgent : public std::enable_shared_from_this<SecureAgent> {
public:
    SecureAgent(asio::io_context& context, const configuration::Agent& config, std::function<void(int)> done)
        : context_(context), config_(config), tls_(security::make_tls_context(config.tls, false)), retry_(context),
          done_(std::move(done)), backoff_(config.reconnect.initial), random_(std::random_device{}()),
          budget_(std::make_shared<BufferBudget>(config.buffer_budget_bytes)),
          metrics_(std::make_shared<observability::Metrics>(observability::Role::agent, std::vector<std::string>{config.name})) {}
    void start() {
        if (config_.metrics && !exporter_) {
            exporter_ = std::make_shared<detail::MetricsServer>(context_, *config_.metrics, metrics_);
            exporter_->start();
        }
        metrics_->budget(observability::Budget::http, budget_->used(), budget_->peak(), budget_->capacity());
        budget_->on_release([owner = weak_from_this()] {
            if (const auto agent = owner.lock()) agent->metrics_->budget(observability::Budget::http,
                agent->budget_->used(), agent->budget_->peak(), agent->budget_->capacity());
        });
        detail::SessionOptions options;
        options.name = config_.name;
        options.timeout = config_.timeout;
        options.write_timeout = config_.write_timeout;
        options.metrics = metrics_;
        const auto owner = std::weak_ptr<SecureAgent>(shared_from_this());
        auto holder = std::make_shared<std::weak_ptr<SecureSession>>();
        auto proxy = std::make_shared<detail::AgentProxy>(context_, config_, [holder](const protocol::tunnel::Frame& frame) {
            if (const auto session = holder->lock()) {
                return session->transmit(frame);
            }
            return false;
        }, budget_, metrics_);
        options.ready = [owner, proxy] {
            if (const auto agent = owner.lock()) agent->ready_at_ = std::chrono::steady_clock::now();
            proxy->start();
        };
        options.message = [proxy](const protocol::tunnel::Frame& frame) { return proxy->message(frame); };
        options.writable = [proxy] { proxy->writable(); };
        options.done = [owner, proxy](const std::string& reason) {
            proxy->stop();
            if (const auto agent = owner.lock()) agent->disconnected(reason);
        };
        session_ = std::make_shared<SecureSession>(tcp::socket(context_), tls_, std::move(options));
        *holder = session_;
        session_->connect(config_.gateway_host, config_.port);
    }
    void stop() {
        if (stopping_) return;
        stopping_ = true;
        retry_.cancel();
        if (session_) session_->stop();
        else complete(0);
    }
private:
    void disconnected(const std::string& reason) {
        session_.reset();
        log(stopping_ ? Level::info : Level::warning, "agent", reason);
        if (stopping_) { complete(0); return; }
        if (!config_.reconnect.enabled) { complete(1); return; }
        // Short-lived authenticated connections must not defeat backoff.
        if (ready_at_ != std::chrono::steady_clock::time_point{} && std::chrono::steady_clock::now() - ready_at_ >= std::chrono::seconds(30))
            backoff_ = config_.reconnect.initial;
        ready_at_ = {};
        std::uniform_int_distribution<long long> jitter(backoff_.count() / 2, backoff_.count());
        const auto delay = std::chrono::milliseconds(jitter(random_));
        backoff_ = std::min(backoff_ * 2, config_.reconnect.maximum);
        log(Level::info, "agent", "reconnect_scheduled delay_ms=" + std::to_string(delay.count()));
        metrics_->event(observability::Event::reconnect);
        retry_.expires_after(delay);
        retry_.async_wait([self = shared_from_this()](Code error) { if (!error && !self->stopping_) self->start(); });
    }
    void complete(int result) {
        if (completed_) return;
        completed_ = true;
        if (exporter_) exporter_->stop();
        done_(result);
    }
    asio::io_context& context_;
    configuration::Agent config_;
    std::shared_ptr<asio::ssl::context> tls_;
    asio::steady_timer retry_;
    std::shared_ptr<SecureSession> session_;
    std::function<void(int)> done_;
    std::chrono::milliseconds backoff_;
    std::chrono::steady_clock::time_point ready_at_{};
    std::mt19937_64 random_;
    std::shared_ptr<BufferBudget> budget_;
    std::shared_ptr<observability::Metrics> metrics_;
    std::shared_ptr<detail::MetricsServer> exporter_;
    bool stopping_ = false, completed_ = false;
};
}
int run_secure_gateway(const configuration::Gateway& config) {
    asio::io_context context;
    auto gateway = std::make_shared<SecureGateway>(context, config);
    asio::signal_set signals(context, SIGINT, SIGTERM);
    signals.async_wait([gateway](Code error, int) { if (!error) gateway->stop(); });
    gateway->start();
    context.run();
    log(Level::info, "gateway", "stopped");
    return 0;
}
int run_secure_agent(const configuration::Agent& config) {
    asio::io_context context;
    asio::signal_set signals(context, SIGINT, SIGTERM);
    int result = 1;
    auto agent = std::make_shared<SecureAgent>(context, config, [&signals, &result](int status) { result = status; signals.cancel(); });
    signals.async_wait([agent](Code error, int) { if (!error) agent->stop(); });
    agent->start();
    context.run();
    return result;
}
} // namespace shadow::networking
