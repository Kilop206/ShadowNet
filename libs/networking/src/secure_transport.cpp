#include <shadow/networking/secure_transport.hpp>
#include "secure_session.hpp"
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

class SecureGateway : public std::enable_shared_from_this<SecureGateway> {
public:
    SecureGateway(asio::io_context& context, const configuration::Gateway& config)
        : tls_(security::make_tls_context(config.tls, true)), acceptor_(context), config_(config) {
        const tcp::endpoint endpoint(asio::ip::make_address(config.bind_host), config.port);
        acceptor_.open(endpoint.protocol());
#ifndef _WIN32
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
#endif
        acceptor_.bind(endpoint);
        acceptor_.listen(static_cast<int>(config.max_connections));
    }
    void start() {
        log(Level::info, "gateway", "wss_listening port=" + std::to_string(config_.port));
        accept();
    }
    void stop() {
        if (stopping_) return;
        stopping_ = true;
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
                Code ignored; socket.close(ignored);
                log(Level::warning, "gateway", "connection_limit_reached");
            } else self->session(std::move(socket));
            self->accept();
        });
    }
    void session(tcp::socket socket) {
        const auto owner = std::weak_ptr<SecureGateway>(shared_from_this());
        auto holder = std::make_shared<std::weak_ptr<SecureSession>>();
        detail::SessionOptions options;
        options.server = true;
        options.timeout = config_.timeout;
        options.interval = config_.heartbeat_interval;
        options.pong_timeout = config_.heartbeat_timeout;
        options.authorize = [owner](const std::string& fingerprint) {
            if (const auto gateway = owner.lock()) {
                for (const auto& agent : gateway->config_.authorized_agents)
                    if (agent.certificate_sha256 == fingerprint) return agent.name;
            }
            return std::string{};
        };
        options.claim = [owner](const std::string& name) {
            const auto gateway = owner.lock();
            return gateway && !gateway->stopping_ && gateway->names_.insert(name).second;
        };
        options.done = [owner, holder](const std::string& reason) {
            if (auto gateway = owner.lock()) {
                if (auto session = holder->lock()) {
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
    std::shared_ptr<asio::ssl::context> tls_;
    tcp::acceptor acceptor_;
    configuration::Gateway config_;
    std::unordered_set<std::shared_ptr<SecureSession>> sessions_;
    std::set<std::string> names_;
    bool stopping_ = false;
};

class SecureAgent : public std::enable_shared_from_this<SecureAgent> {
public:
    SecureAgent(asio::io_context& context, const configuration::Agent& config, std::function<void(int)> done)
        : context_(context), config_(config), tls_(security::make_tls_context(config.tls, false)), retry_(context),
          done_(std::move(done)), backoff_(config.reconnect.initial), random_(std::random_device{}()) {}
    void start() {
        detail::SessionOptions options;
        options.name = config_.name;
        options.timeout = config_.timeout;
        const auto owner = std::weak_ptr<SecureAgent>(shared_from_this());
        options.ready = [owner] { if (const auto agent = owner.lock()) agent->ready_at_ = std::chrono::steady_clock::now(); };
        options.done = [owner](const std::string& reason) { if (const auto agent = owner.lock()) agent->disconnected(reason); };
        session_ = std::make_shared<SecureSession>(tcp::socket(context_), tls_, std::move(options));
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
        retry_.expires_after(delay);
        retry_.async_wait([self = shared_from_this()](Code error) { if (!error && !self->stopping_) self->start(); });
    }
    void complete(int result) {
        if (completed_) return;
        completed_ = true;
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
