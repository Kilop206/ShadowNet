#include "https_server.hpp"
#include <shadow/core/error.hpp>
#include <shadow/security/tls.hpp>
#include <shadow/observability/log.hpp>
#include <utility>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <unordered_set>
#include <optional>
#include <charconv>

namespace shadow::networking::detail {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace px = protocol::proxy;
using tcp = asio::ip::tcp;
using Code = boost::system::error_code;
namespace {
class Frontend : public std::enable_shared_from_this<Frontend> {
public:
    Frontend(tcp::socket socket, std::shared_ptr<asio::ssl::context> tls, std::chrono::milliseconds timeout,
        Dispatch dispatch, std::function<void()> done)
        : tls_(std::move(tls)), stream_(std::move(socket), *tls_), timer_(stream_.get_executor()),
          timeout_(timeout), dispatch_(std::move(dispatch)), done_(std::move(done)) {
        Code error;
        const auto endpoint = stream_.next_layer().remote_endpoint(error);
        if (!error) client_ip_ = endpoint.address().to_string();
        parser_.header_limit(static_cast<std::uint32_t>(px::max_headers));
        parser_.body_limit(px::max_body);
    }
    void start() {
        arm(timeout_);
        stream_.async_handshake(asio::ssl::stream_base::server, [self = shared_from_this()](Code error) {
            if (self->closed_) return;
            if (error) { self->stop(); return; }
            http::async_read_header(self->stream_, self->buffer_, self->parser_, [self](Code read_error, std::size_t) {
                if (self->closed_) return;
                if (read_error) { self->parse_error(read_error); return; }
                self->header();
            });
        });
    }
    void stop() {
        if (closed_) return;
        closed_ = true;
        ++timer_generation_;
        timer_.cancel();
        if (cancel_) { auto cancel = std::move(cancel_); cancel(); }
        Code ignored;
        stream_.next_layer().shutdown(tcp::socket::shutdown_both, ignored);
        stream_.next_layer().close(ignored);
        const auto keep_alive = shared_from_this();
        auto done = std::move(done_); done();
    }
private:
    void arm(std::chrono::milliseconds timeout) {
        const auto generation = ++timer_generation_;
        timer_.expires_after(timeout);
        timer_.async_wait([self = shared_from_this(), generation](Code error) {
            if (!error && generation == self->timer_generation_) self->stop();
        });
    }
    void parse_error(Code error) {
        if (error == http::error::end_of_stream || error == asio::error::operation_aborted) { stop(); return; }
        respond(px::error_response(0, error == http::error::body_limit ? 413 : error == http::error::header_limit ? 431 : 400));
    }
    px::Fields fields() const {
        px::Fields result;
        for (const auto& field : parser_.get().base()) result.emplace_back(px::lower(field.name_string()), std::string(field.value()));
        return result;
    }
    void header() {
        auto& request = parser_.get();
        method_ = std::string(request.method_string());
        if (request.version() != 11) { respond(px::error_response(0, 505)); return; }
        if (method_ == "CONNECT" || method_ == "TRACE") { respond(px::error_response(0, 405)); return; }
        if (request.count(http::field::upgrade) != 0) { respond(px::error_response(0, 501)); return; }
        try {
            if (px::loops_to_gateway(fields())) { respond(px::error_response(0, 508)); return; }
            px::validate_target(method_, request.target());
            (void)px::sanitize_request(fields(), client_ip_);
            const auto max_forwards = px::single_field(fields(), "max-forwards");
            if (method_ == "OPTIONS" && !max_forwards.empty()) {
                std::uint64_t value = 0;
                const auto parsed = std::from_chars(max_forwards.data(), max_forwards.data() + max_forwards.size(), value);
                if (parsed.ec != std::errc{} || parsed.ptr != max_forwards.data() + max_forwards.size()) throw Error("invalid Max-Forwards");
                if (value == 0) {
                    respond({0, 200, "OK", {{"allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"}}, ""}); return;
                }
                request.set(http::field::max_forwards, std::to_string(value - 1));
            }
        } catch (const Error&) { respond(px::error_response(0, 400)); return; }
        if (request.count(http::field::expect) != 0) {
            if (request.count(http::field::expect) != 1 || px::lower(request[http::field::expect]) != "100-continue") {
                respond(px::error_response(0, 417)); return;
            }
            interim_.emplace(http::status::continue_, 11);
            http::async_write(stream_, *interim_, [self = shared_from_this()](Code error, std::size_t) {
                if (self->closed_) return;
                if (error) { self->stop(); return; }
                self->read_body();
            });
        } else read_body();
    }
    void read_body() {
        http::async_read(stream_, buffer_, parser_, [self = shared_from_this()](Code error, std::size_t) {
            if (self->closed_) return;
            if (error) { self->parse_error(error); return; }
            try {
                auto message = self->parser_.release();
                px::Fields fields;
                for (const auto& field : message.base()) fields.emplace_back(px::lower(field.name_string()), std::string(field.value()));
                px::Request request{0, "", std::string(message.method_string()), std::string(message.target()),
                    px::sanitize_request(fields, self->client_ip_), std::move(message.body())};
                ++self->timer_generation_; self->timer_.cancel();
                self->cancel_ = self->dispatch_(std::move(request), [owner = std::weak_ptr<Frontend>(self)](px::Response response) {
                    if (const auto frontend = owner.lock()) frontend->respond(std::move(response));
                });
            } catch (const Error&) { self->respond(px::error_response(0, 400)); }
        });
    }
    void respond(px::Response response) {
        if (closed_ || response_) return;
        try {
            const bool head = method_ == "HEAD";
            auto fields = px::sanitize(response.fields, head || response.status == 304);
            response_.emplace(static_cast<http::status>(response.status), 11);
            if (!response.reason.empty()) response_->reason(response.reason);
            for (const auto& [key, value] : fields) response_->insert(key, value);
            response_->insert(http::field::via, "1.1 shadownet");
            response_->keep_alive(false);
            if (head) {
                if (response.id == 0) response_->content_length(response.body.size());
            } else if (response.status == 204 || response.status == 304) {
                if (response.status == 204) response_->erase(http::field::content_length);
            } else {
                response_->body() = std::move(response.body);
                response_->prepare_payload();
            }
            auto& serializer = serializer_.emplace(*response_);
            arm(timeout_);
            auto written = [self = shared_from_this()](Code error, std::size_t) {
                if (self->closed_) return;
                if (error) { self->stop(); return; }
                self->arm(std::chrono::milliseconds(1000));
                self->stream_.async_shutdown([self](Code) { self->stop(); });
            };
            if (head) http::async_write_header(stream_, serializer, std::move(written));
            else http::async_write(stream_, serializer, std::move(written));
        } catch (const Error&) { stop(); }
    }
    std::shared_ptr<asio::ssl::context> tls_;
    asio::ssl::stream<tcp::socket> stream_;
    asio::steady_timer timer_;
    std::chrono::milliseconds timeout_;
    Dispatch dispatch_;
    std::function<void()> done_;
    CancelRequest cancel_;
    http::request_parser<http::string_body> parser_;
    beast::flat_buffer buffer_{px::max_headers + 8192};
    std::optional<http::response<http::empty_body>> interim_;
    std::optional<http::response<http::string_body>> response_;
    std::optional<http::response_serializer<http::string_body>> serializer_;
    std::string client_ip_, method_;
    std::uint64_t timer_generation_ = 0;
    bool closed_ = false;
};
}
class HttpsServer::Impl : public std::enable_shared_from_this<Impl> {
public:
    Impl(asio::io_context& context, configuration::Https config, Dispatch dispatch)
        : config_(std::move(config)), tls_(security::make_https_context(config_.tls)), acceptor_(context), dispatch_(std::move(dispatch)) {
        const tcp::endpoint endpoint(asio::ip::make_address(config_.bind_host), config_.port);
        acceptor_.open(endpoint.protocol());
#ifndef _WIN32
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
#endif
        acceptor_.bind(endpoint); acceptor_.listen(static_cast<int>(config_.max_connections));
    }
    void start() {
        observability::log(observability::Level::info, "gateway", "https_listening port=" + std::to_string(config_.port));
        accept();
    }
    void stop() {
        if (stopping_) return;
        stopping_ = true;
        Code ignored; acceptor_.close(ignored);
        const auto sessions = sessions_;
        for (const auto& session : sessions) session->stop();
    }
private:
    void accept() {
        acceptor_.async_accept([self = shared_from_this()](Code error, tcp::socket socket) {
            if (self->stopping_) return;
            if (error) throw Error("HTTPS listener failed");
            if (self->sessions_.size() >= self->config_.max_connections) { Code ignored; socket.close(ignored); }
            else {
                auto holder = std::make_shared<std::weak_ptr<Frontend>>();
                auto session = std::make_shared<Frontend>(std::move(socket), self->tls_, self->config_.timeout, self->dispatch_,
                    [owner = std::weak_ptr<Impl>(self), holder] {
                        if (const auto server = owner.lock()) if (const auto frontend = holder->lock()) server->sessions_.erase(frontend);
                    });
                *holder = session; self->sessions_.insert(session); session->start();
            }
            self->accept();
        });
    }
    configuration::Https config_;
    std::shared_ptr<asio::ssl::context> tls_;
    tcp::acceptor acceptor_;
    Dispatch dispatch_;
    std::unordered_set<std::shared_ptr<Frontend>> sessions_;
    bool stopping_ = false;
};
HttpsServer::HttpsServer(asio::io_context& context, configuration::Https config, Dispatch dispatch)
    : impl_(std::make_shared<Impl>(context, std::move(config), std::move(dispatch))) {}
HttpsServer::~HttpsServer() = default;
void HttpsServer::start() { impl_->start(); }
void HttpsServer::stop() { impl_->stop(); }
} // namespace shadow::networking::detail
