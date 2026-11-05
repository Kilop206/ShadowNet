#include "secure_session.hpp"
#include <shadow/core/error.hpp>
#include <shadow/observability/log.hpp>
#include <shadow/protocol/tunnel.hpp>
#include <utility>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <deque>
#include <limits>
#include <vector>

namespace shadow::networking::detail {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace wire = protocol::tunnel;
using tcp = asio::ip::tcp;
using Code = boost::system::error_code;
using observability::Level;
using observability::log;

class SecureSession::Impl : public std::enable_shared_from_this<Impl> {
public:
    Impl(tcp::socket socket, std::shared_ptr<asio::ssl::context> tls, SessionOptions options)
        : tls_(std::move(tls)), ws_(std::move(socket), *tls_), resolver_(ws_.get_executor()),
          deadline_(ws_.get_executor()), heartbeat_(ws_.get_executor()), options_(std::move(options)), name_(options_.name) {
        ws_.read_message_max(wire::control_message);
        ws_.write_buffer_bytes(512);
        ws_.binary(true);
        ws_.set_option(websocket::stream_base::timeout{options_.timeout, websocket::stream_base::none(), false});
        request_.header_limit(8192);
        request_.body_limit(0);
    }
    void accept() {
        observe_close();
        arm_deadline(options_.timeout, "handshake_timeout");
        tls_handshake(asio::ssl::stream_base::server);
    }
    void connect(const std::string& host, std::uint16_t port) {
        observe_close();
        host_ = host;
        authority_ = (host.find(':') == std::string::npos ? host : "[" + host + "]") + ":" + std::to_string(port);
        security::verify_server_identity(ws_.next_layer().native_handle(), host);
        arm_deadline(options_.timeout, "handshake_timeout");
        resolver_.async_resolve(host, std::to_string(port), [self = shared_from_this()](Code error, const tcp::resolver::results_type& endpoints) {
            if (self->closed_) return;
            if (error) { self->finish("resolve_failed"); return; }
            beast::get_lowest_layer(self->ws_).async_connect(endpoints, [self](Code connect_error, const tcp::endpoint&) {
                if (self->closed_) return;
                if (connect_error) { self->finish("connection_failed"); return; }
                self->tls_handshake(asio::ssl::stream_base::client);
            });
        });
    }
    void stop() { graceful(true); }
    const std::string& name() const { return name_; }
    bool claimed() const { return claimed_; }
    bool transmit(const wire::Frame& frame) {
        if (!active_ || closed_ || stopping_ || frame.type < wire::Type::register_services) return false;
        return send(frame);
    }

private:
    void observe_close() {
        ws_.control_callback([owner = std::weak_ptr<Impl>(shared_from_this())](websocket::frame_type type, beast::string_view) {
            if (type != websocket::frame_type::close) return;
            if (const auto self = owner.lock()) {
                self->stopping_ = true;
                ++self->heartbeat_generation_;
                self->heartbeat_.cancel();
                self->arm_deadline(std::chrono::milliseconds(1000), "shutdown_timeout");
            }
        });
    }
    void arm_deadline(std::chrono::milliseconds timeout, std::string reason) {
        const auto generation = ++deadline_generation_;
        deadline_.expires_after(timeout);
        deadline_.async_wait([self = shared_from_this(), generation, reason = std::move(reason)](Code error) {
            if (!error && generation == self->deadline_generation_) self->finish(reason);
        });
    }
    void cancel_deadline() { ++deadline_generation_; deadline_.cancel(); }
    void tls_handshake(asio::ssl::stream_base::handshake_type role) {
        ws_.next_layer().async_handshake(role, [self = shared_from_this()](Code error) {
            if (self->closed_) return;
            if (error || SSL_version(self->ws_.next_layer().native_handle()) != TLS1_3_VERSION) {
                self->finish("tls_handshake_failed"); return;
            }
            try {
                const auto fingerprint = security::peer_fingerprint(self->ws_.next_layer().native_handle());
                if (self->options_.server) {
                    self->name_ = self->options_.authorize(fingerprint);
                    if (self->name_.empty()) { self->finish("agent_not_authorized"); return; }
                    self->read_upgrade();
                } else self->upgrade_client();
            } catch (const Error&) { self->finish("peer_verification_failed"); }
        });
    }
    void read_upgrade() {
        http::async_read(ws_.next_layer(), upgrade_buffer_, request_, [self = shared_from_this()](Code error, std::size_t) {
            if (self->closed_) return;
            if (error) { self->finish("websocket_upgrade_rejected"); return; }
            const auto& request = self->request_.get();
            if (request.method() != http::verb::get || request.version() != 11 || request.target() != wire::path ||
                request[http::field::sec_websocket_protocol] != wire::subprotocol || request.count(http::field::origin) != 0 ||
                !websocket::is_upgrade(request) || self->upgrade_buffer_.size() != 0) {
                self->finish("websocket_upgrade_rejected"); return;
            }
            self->ws_.set_option(websocket::stream_base::decorator([](websocket::response_type& response) {
                response.set(http::field::sec_websocket_protocol, wire::subprotocol);
            }));
            self->ws_.async_accept(request, [self](Code upgrade_error) {
                if (self->closed_) return;
                if (upgrade_error) { self->finish("websocket_upgrade_failed"); return; }
                self->read();
            });
        });
    }
    void upgrade_client() {
        ws_.set_option(websocket::stream_base::decorator([](websocket::request_type& request) {
            request.set(http::field::sec_websocket_protocol, wire::subprotocol);
        }));
        ws_.async_handshake(upgrade_response_, authority_, wire::path, [self = shared_from_this()](Code error) {
            if (self->closed_) return;
            if (error || self->upgrade_response_[http::field::sec_websocket_protocol] != wire::subprotocol) {
                self->finish("websocket_upgrade_failed"); return;
            }
            self->send({wire::Type::hello, self->name_});
            self->read();
        });
    }
    void read() {
        ws_.async_read(read_buffer_, [self = shared_from_this()](Code error, std::size_t) {
            if (self->closed_) return;
            if (error == websocket::error::closed) {
                // Beast's SSL teardown already exchanges close_notify and closes TCP.
                if (!self->close_started_) self->finish("tunnel_closed");
                return;
            }
            if (error) {
                if (!self->close_started_) self->finish("tunnel_disconnected");
                return;
            }
            if (self->stopping_) return;
            try {
                if (!self->ws_.got_binary()) throw Error("text frames are forbidden");
                const auto data = self->read_buffer_.data();
                const auto* first = static_cast<const std::uint8_t*>(data.data());
                auto frame = wire::decode(std::span(first, data.size()));
                self->read_buffer_.consume(self->read_buffer_.size());
                self->message(frame);
            } catch (const Error&) { self->finish("invalid_tunnel_message"); return; }
            if (!self->closed_ && !self->stopping_) self->read();
        });
    }
    void message(const wire::Frame& frame) {
        if (!active_) {
            if (options_.server) {
                if (frame.type != wire::Type::hello || frame.payload != name_) throw Error("HELLO identity mismatch");
                claimed_ = options_.claim(name_);
                if (!claimed_) { finish("duplicate_agent_session"); return; }
                session_id_ = security::random_session_id();
                send({wire::Type::welcome, wire::encode_welcome({session_id_, options_.interval, options_.pong_timeout})});
            } else {
                if (frame.type != wire::Type::welcome) throw Error("expected WELCOME");
                const auto welcome = wire::decode_welcome(frame.payload);
                session_id_ = welcome.session_id;
                options_.interval = welcome.interval;
                options_.pong_timeout = welcome.timeout;
            }
            active_ = true;
            ws_.read_message_max(wire::max_message);
            cancel_deadline();
            log(Level::info, options_.server ? "gateway" : "agent", "tunnel_established session=" + session_id_);
            if (options_.ready) options_.ready();
            if (options_.server) expect_ping(); else schedule_ping();
            return;
        }
        if (frame.type == wire::Type::goodbye) { graceful(false); return; }
        if (frame.type >= wire::Type::register_services) {
            if (!options_.message || !options_.message(frame)) throw Error("invalid proxy state");
            return;
        }
        if (options_.server) {
            if (frame.type != wire::Type::ping || sequence_ == std::numeric_limits<std::uint64_t>::max() ||
                frame.payload != wire::heartbeat_id(sequence_ + 1)) throw Error("unexpected heartbeat sequence");
            ++sequence_;
            send({wire::Type::pong, frame.payload});
            expect_ping();
        } else {
            if (frame.type != wire::Type::pong || !waiting_pong_ || frame.payload != wire::heartbeat_id(sequence_))
                throw Error("unexpected PONG");
            waiting_pong_ = false;
            log(Level::info, "agent", "heartbeat_confirmed");
            schedule_ping();
        }
    }
    void expect_ping() {
        const auto generation = ++heartbeat_generation_;
        heartbeat_.expires_after(options_.interval + options_.pong_timeout);
        heartbeat_.async_wait([self = shared_from_this(), generation](Code error) {
            if (!error && generation == self->heartbeat_generation_ && !self->stopping_) self->finish("heartbeat_timeout");
        });
    }
    void schedule_ping() {
        const auto generation = ++heartbeat_generation_;
        heartbeat_.expires_after(options_.interval);
        heartbeat_.async_wait([self = shared_from_this(), generation](Code error) {
            if (error || generation != self->heartbeat_generation_ || self->stopping_ || self->closed_) return;
            if (self->sequence_ == std::numeric_limits<std::uint64_t>::max()) { self->finish("heartbeat_sequence_exhausted"); return; }
            self->waiting_pong_ = true;
            ++self->sequence_;
            self->send({wire::Type::ping, wire::heartbeat_id(self->sequence_)});
            const auto pending_generation = ++self->heartbeat_generation_;
            self->heartbeat_.expires_after(self->options_.pong_timeout);
            self->heartbeat_.async_wait([self, pending_generation](Code timeout_error) {
                if (!timeout_error && pending_generation == self->heartbeat_generation_ && self->waiting_pong_ && !self->stopping_)
                    self->finish("heartbeat_timeout");
            });
        });
    }
    bool send(const wire::Frame& frame) {
        if (closed_) return false;
        auto bytes = std::make_shared<std::vector<std::uint8_t>>(wire::encode(frame));
        if (writes_.size() >= 64 || queued_bytes_ + bytes->size() > 4 * wire::max_message) {
            if (frame.type <= wire::Type::goodbye) finish("write_queue_limit");
            return false;
        }
        const bool idle = writes_.empty();
        queued_bytes_ += bytes->size();
        writes_.push_back(std::move(bytes));
        if (idle) write();
        return true;
    }
    void write() {
        const auto bytes = writes_.front();
        ws_.async_write(asio::buffer(*bytes), [self = shared_from_this(), bytes](Code error, std::size_t) {
            if (self->closed_) return;
            if (error) { self->finish("tunnel_write_failed"); return; }
            self->queued_bytes_ -= bytes->size();
            self->writes_.pop_front();
            if (!self->writes_.empty()) self->write();
            else if (self->stopping_) self->close_websocket();
        });
    }
    void graceful(bool notify) {
        if (closed_ || stopping_) return;
        if (!active_ || !ws_.is_open()) { finish("shutdown"); return; }
        stopping_ = true;
        ++heartbeat_generation_;
        heartbeat_.cancel();
        arm_deadline(std::chrono::milliseconds(1000), "shutdown_timeout");
        if (notify) send({wire::Type::goodbye, "shutdown"});
        else if (writes_.empty()) close_websocket();
    }
    void close_websocket() {
        if (close_started_ || closed_) return;
        close_started_ = true;
        ws_.async_close(websocket::close_code::normal, [self = shared_from_this()](Code error) {
            if (self->closed_) return;
            if (error) { self->finish("websocket_close_failed"); return; }
            self->finish("tunnel_closed");
        });
    }
    void finish(const std::string& reason) {
        if (closed_) return;
        closed_ = true;
        cancel_deadline();
        ++heartbeat_generation_;
        heartbeat_.cancel();
        resolver_.cancel();
        Code ignored;
        auto& socket = beast::get_lowest_layer(ws_).socket();
        socket.shutdown(tcp::socket::shutdown_both, ignored);
        socket.close(ignored);
        const auto keep_alive = shared_from_this();
        auto done = std::move(options_.done);
        done(reason);
    }

    std::shared_ptr<asio::ssl::context> tls_;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>, false> ws_;
    tcp::resolver resolver_;
    asio::steady_timer deadline_, heartbeat_;
    SessionOptions options_;
    std::string name_, host_, authority_, session_id_;
    beast::flat_buffer read_buffer_{wire::max_message};
    beast::flat_buffer upgrade_buffer_{8192};
    http::request_parser<http::empty_body> request_;
    websocket::response_type upgrade_response_;
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> writes_;
    std::size_t queued_bytes_ = 0;
    std::uint64_t sequence_ = 0, deadline_generation_ = 0, heartbeat_generation_ = 0;
    bool active_ = false, closed_ = false, stopping_ = false, claimed_ = false;
    bool waiting_pong_ = false, close_started_ = false;
};

SecureSession::SecureSession(tcp::socket socket, std::shared_ptr<asio::ssl::context> tls, SessionOptions options)
    : impl_(std::make_shared<Impl>(std::move(socket), std::move(tls), std::move(options))) {}
SecureSession::~SecureSession() = default;
void SecureSession::accept() { impl_->accept(); }
void SecureSession::connect(const std::string& host, std::uint16_t port) { impl_->connect(host, port); }
void SecureSession::stop() { impl_->stop(); }
const std::string& SecureSession::name() const { return impl_->name(); }
bool SecureSession::claimed() const { return impl_->claimed(); }
bool SecureSession::transmit(const protocol::tunnel::Frame& frame) { return impl_->transmit(frame); }
} // namespace shadow::networking::detail
