#include "metrics_server.hpp"
#include <shadow/core/error.hpp>
#include <shadow/observability/log.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <optional>
#include <unordered_set>

namespace shadow::networking::detail {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using Code = boost::system::error_code;
namespace {
class Scrape : public std::enable_shared_from_this<Scrape> {
public:
    Scrape(tcp::socket socket, configuration::MetricsEndpoint config, std::shared_ptr<observability::Metrics> metrics, std::function<void()> done)
        : socket_(std::move(socket)), timer_(socket_.get_executor()), config_(std::move(config)), metrics_(std::move(metrics)), done_(std::move(done)) {
        parser_.header_limit(4096); parser_.body_limit(0);
    }
    void start() {
        timer_.expires_after(config_.timeout);
        timer_.async_wait([self = shared_from_this()](Code error) { if (!error) self->stop(); });
        http::async_read(socket_, buffer_, parser_, [self = shared_from_this()](Code error, std::size_t) {
            if (self->closed_) return;
            if (error) { self->reply(400); return; }
            const auto& request = self->parser_.get();
            self->head_ = request.method() == http::verb::head;
            const auto authority = request[http::field::host];
            bool local = false;
            for (const auto* host : {"127.0.0.1", "[::1]", "localhost"}) {
                if (authority == host || authority == std::string(host) + ":" + std::to_string(self->config_.port)) local = true;
            }
            if (request.version() != 11 || request.count(http::field::host) != 1 || !local || request.count(http::field::origin) != 0 ||
                request.count(http::field::transfer_encoding) != 0 || request.payload_size().value_or(0) != 0) { self->reply(400); return; }
            if (request.method() != http::verb::get && !self->head_) { self->reply(405); return; }
            if (request.target() != "/metrics") { self->reply(404); return; }
            self->metrics_->scrape();
            self->reply(200);
        });
    }
    void stop() {
        if (closed_) return;
        closed_ = true; timer_.cancel();
        Code ignored; socket_.shutdown(tcp::socket::shutdown_both, ignored); socket_.close(ignored);
        const auto keep_alive = shared_from_this(); auto done = std::move(done_); done();
    }
private:
    void reply(unsigned status) {
        if (response_ || closed_) return;
        response_.emplace(static_cast<http::status>(status), 11);
        response_->set(http::field::cache_control, "no-store");
        response_->keep_alive(false);
        if (status == 200) {
            response_->set(http::field::content_type, "text/plain; version=0.0.4; charset=utf-8");
            response_->body() = metrics_->render();
            if (response_->body().size() > 262144) { stop(); return; }
        } else {
            response_->set(http::field::content_type, "text/plain; charset=utf-8");
            if (status == 405) response_->set(http::field::allow, "GET, HEAD");
            response_->body() = "Metrics request rejected\n";
        }
        response_->prepare_payload();
        auto& serializer = serializer_.emplace(*response_);
        auto done = [self = shared_from_this()](Code, std::size_t) { self->stop(); };
        if (head_) http::async_write_header(socket_, serializer, std::move(done));
        else http::async_write(socket_, serializer, std::move(done));
    }
    tcp::socket socket_;
    asio::steady_timer timer_;
    configuration::MetricsEndpoint config_;
    std::shared_ptr<observability::Metrics> metrics_;
    std::function<void()> done_;
    http::request_parser<http::empty_body> parser_;
    beast::flat_buffer buffer_{8192};
    std::optional<http::response<http::string_body>> response_;
    std::optional<http::response_serializer<http::string_body>> serializer_;
    bool closed_ = false, head_ = false;
};
}
class MetricsServer::Impl : public std::enable_shared_from_this<Impl> {
public:
    Impl(asio::io_context& context, configuration::MetricsEndpoint config, std::shared_ptr<observability::Metrics> metrics)
        : acceptor_(context), config_(std::move(config)), metrics_(std::move(metrics)) {
        const tcp::endpoint endpoint(asio::ip::make_address(config_.bind_host), config_.port);
        if (!endpoint.address().is_loopback()) throw Error("metrics listener must use loopback");
        acceptor_.open(endpoint.protocol());
#ifndef _WIN32
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
#endif
        acceptor_.bind(endpoint); acceptor_.listen(static_cast<int>(config_.max_connections));
    }
    void start() {
        observability::log(observability::Level::info, "metrics", "metrics_listening port=" + std::to_string(config_.port)); accept();
    }
    void stop() {
        if (stopped_) return;
        stopped_ = true; Code ignored; acceptor_.close(ignored);
        const auto sessions = sessions_;
        for (const auto& session : sessions) session->stop();
    }
private:
    void accept() {
        acceptor_.async_accept([self = shared_from_this()](Code error, tcp::socket socket) {
            if (self->stopped_) return;
            if (error) throw Error("metrics listener failed");
            if (self->sessions_.size() >= self->config_.max_connections) { Code ignored; socket.close(ignored); }
            else {
                auto holder = std::make_shared<std::weak_ptr<Scrape>>();
                auto session = std::make_shared<Scrape>(std::move(socket), self->config_, self->metrics_, [owner = std::weak_ptr<Impl>(self), holder] {
                    if (const auto server = owner.lock()) if (const auto current = holder->lock()) server->sessions_.erase(current);
                });
                *holder = session; self->sessions_.insert(session); session->start();
            }
            self->accept();
        });
    }
    tcp::acceptor acceptor_;
    configuration::MetricsEndpoint config_;
    std::shared_ptr<observability::Metrics> metrics_;
    std::unordered_set<std::shared_ptr<Scrape>> sessions_;
    bool stopped_ = false;
};
MetricsServer::MetricsServer(asio::io_context& context, configuration::MetricsEndpoint config, std::shared_ptr<observability::Metrics> metrics)
    : impl_(std::make_shared<Impl>(context, std::move(config), std::move(metrics))) {}
MetricsServer::~MetricsServer() = default;
void MetricsServer::start() { impl_->start(); }
void MetricsServer::stop() { impl_->stop(); }
} // namespace shadow::networking::detail
