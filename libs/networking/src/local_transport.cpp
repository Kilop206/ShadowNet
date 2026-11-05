#include <shadow/networking/local_transport.hpp>
#include <shadow/core/error.hpp>
#include <shadow/observability/log.hpp>
#include <shadow/protocol/message.hpp>
#include <shadow/security/validation.hpp>
#include <utility>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <array>
#include <csignal>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace shadow::networking {
namespace {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using Code = boost::system::error_code;
using observability::Level;
using observability::log;

class Exchange : public std::enable_shared_from_this<Exchange> {
public:
    using Completion = std::function<void(bool, const std::string&)>;
    Exchange(tcp::socket socket, std::chrono::milliseconds timeout, std::string name, Completion done)
        : socket_(std::move(socket)), timer_(socket_.get_executor()), timeout_(timeout),
          name_(std::move(name)), done_(std::move(done)) {}

    void receive() { arm_deadline(); read_header(); }
    void connect(const tcp::endpoint& endpoint) {
        arm_deadline();
        socket_.async_connect(endpoint, [self = shared_from_this()](Code error) {
            if (self->finished_) return;
            if (error) { self->finish(false, "connection_failed"); return; }
            self->outgoing_ = true;
            self->write({protocol::Type::hello, self->name_});
        });
    }
    void cancel() { finish(false, "cancelled"); }

private:
    void arm_deadline() {
        timer_.expires_after(timeout_);
        timer_.async_wait([self = shared_from_this()](Code error) {
            if (!error) self->finish(false, "handshake_timeout");
        });
    }
    void read_header() {
        asio::async_read(socket_, asio::buffer(header_bytes_), [self = shared_from_this()](Code error, std::size_t) {
            if (self->finished_) return;
            if (error) { self->finish(false, "header_read_failed"); return; }
            try {
                self->header_ = protocol::decode_header(self->header_bytes_);
                const auto expected = self->outgoing_ ? protocol::Type::hello_ack : protocol::Type::hello;
                if (self->header_.type != expected) throw Error("unexpected handshake message");
                self->body_.resize(self->header_.payload_size);
            } catch (const Error&) {
                self->finish(false, "invalid_header");
                return;
            }
            self->read_body();
        });
    }
    void read_body() {
        asio::async_read(socket_, asio::buffer(body_), [self = shared_from_this()](Code error, std::size_t) {
            if (self->finished_) return;
            if (error) { self->finish(false, "body_read_failed"); return; }
            try {
                auto message = protocol::decode_payload(self->header_, self->body_);
                if (self->outgoing_) {
                    if (message.name != self->name_) throw Error("mismatched acknowledgement");
                    self->finish(true, "hello_acknowledged");
                } else {
                    self->write({protocol::Type::hello_ack, std::move(message.name)});
                }
            } catch (const Error&) {
                self->finish(false, "invalid_handshake");
            }
        });
    }
    void write(const protocol::Message& message) {
        write_bytes_ = protocol::encode(message);
        asio::async_write(socket_, asio::buffer(write_bytes_), [self = shared_from_this()](Code error, std::size_t) {
            if (self->finished_) return;
            if (error) { self->finish(false, "write_failed"); return; }
            if (self->outgoing_) self->read_header();
            else self->finish(true, "local_handshake_completed");
        });
    }
    void finish(bool success, const std::string& reason) {
        if (finished_) return;
        finished_ = true;
        timer_.cancel();
        Code ignored;
        socket_.shutdown(tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
        // Keep this instance alive while the owner removes its session reference.
        const auto keep_alive = shared_from_this();
        auto done = std::move(done_);
        done(success, reason);
    }

    tcp::socket socket_;
    asio::steady_timer timer_;
    std::chrono::milliseconds timeout_;
    std::string name_;
    Completion done_;
    std::array<std::uint8_t, protocol::header_size> header_bytes_{};
    protocol::Header header_{protocol::Type::hello, 0};
    std::vector<std::uint8_t> body_;
    std::vector<std::uint8_t> write_bytes_;
    bool outgoing_ = false;
    bool finished_ = false;
};

class LocalGateway : public std::enable_shared_from_this<LocalGateway> {
public:
    LocalGateway(asio::io_context& context, const configuration::Gateway& config)
        : acceptor_(context), config_(config) {
        if (!security::is_loopback(config.bind_host) || config.port == 0 || config.max_connections == 0 ||
            config.max_connections > 1024 || config.timeout.count() < 100 || config.timeout.count() > 60000)
            throw Error("invalid local gateway configuration");
        const tcp::endpoint endpoint(asio::ip::make_address(config.bind_host), config.port);
        acceptor_.open(endpoint.protocol());
        // Deliberately avoid SO_REUSEADDR on Windows (port hijacking semantics).
#ifndef _WIN32
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
#endif
        acceptor_.bind(endpoint);
        acceptor_.listen(static_cast<int>(config.max_connections));
    }
    void start() {
        log(Level::warning, "gateway", "local_tcp_diagnostic_without_tls");
        log(Level::info, "gateway", "listening port=" + std::to_string(config_.port));
        accept();
    }
    void stop() {
        if (stopped_) return;
        stopped_ = true;
        Code ignored;
        acceptor_.close(ignored);
        const auto sessions = sessions_; // cancel() removes entries from the original set.
        for (const auto& session : sessions) session->cancel();
        log(Level::info, "gateway", "stopped");
    }
private:
    void accept() {
        acceptor_.async_accept([self = shared_from_this()](Code error, tcp::socket socket) {
            if (self->stopped_) return;
            if (error) throw Error("gateway accept failed");
            if (self->sessions_.size() >= self->config_.max_connections) {
                Code ignored;
                socket.close(ignored);
                log(Level::warning, "gateway", "connection_limit_reached");
            } else {
                // Holder gives completion a weak reference without an ownership cycle.
                auto holder = std::make_shared<std::weak_ptr<Exchange>>();
                auto session = std::make_shared<Exchange>(std::move(socket), self->config_.timeout, "",
                    [owner = std::weak_ptr<LocalGateway>(self), holder](bool success, const std::string& reason) {
                        if (auto gateway = owner.lock()) {
                            if (auto exchange = holder->lock()) gateway->sessions_.erase(exchange);
                            log(success ? Level::info : Level::warning, "gateway", reason);
                        }
                    });
                *holder = session;
                self->sessions_.insert(session);
                session->receive();
            }
            self->accept();
        });
    }
    tcp::acceptor acceptor_;
    configuration::Gateway config_;
    std::unordered_set<std::shared_ptr<Exchange>> sessions_;
    bool stopped_ = false;
};
}
int run_gateway(const configuration::Gateway& config) {
    asio::io_context context;
    auto gateway = std::make_shared<LocalGateway>(context, config);
    asio::signal_set signals(context, SIGINT, SIGTERM);
    signals.async_wait([gateway](Code error, int) { if (!error) gateway->stop(); });
    gateway->start();
    context.run();
    return 0;
}
int run_agent(const configuration::Agent& config) {
    if (!security::is_loopback(config.gateway_host) || !security::valid_identifier(config.name) || config.port == 0 ||
        config.timeout.count() < 100 || config.timeout.count() > 60000) throw Error("invalid local agent configuration");
    asio::io_context context;
    asio::signal_set signals(context, SIGINT, SIGTERM);
    int result = 1;
    auto probe = std::make_shared<Exchange>(tcp::socket(context), config.timeout, config.name,
        [&result, &signals](bool success, const std::string& reason) {
            result = success ? 0 : 1;
            log(success ? Level::info : Level::error, "agent", reason);
            signals.cancel();
        });
    signals.async_wait([probe](Code error, int) { if (!error) probe->cancel(); });
    log(Level::warning, "agent", "local_tcp_diagnostic_without_tls");
    probe->connect({asio::ip::make_address(config.gateway_host), config.port});
    context.run();
    return result;
}
} // namespace shadow::networking
