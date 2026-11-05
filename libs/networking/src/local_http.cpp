#include "local_http.hpp"
#include <shadow/core/error.hpp>
#include <utility>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>

namespace shadow::networking::detail {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace px = protocol::proxy;
using tcp = asio::ip::tcp;
using Code = boost::system::error_code;

class LocalHttp::Impl : public std::enable_shared_from_this<Impl> {
public:
    Impl(asio::io_context& context, const configuration::Service& service, px::Request request,
        std::chrono::milliseconds timeout, Completion done)
        : socket_(context), timer_(context), endpoint_(asio::ip::make_address(service.local_host), service.local_port),
          timeout_(timeout), done_(std::move(done)), id_(request.id), head_(request.method == "HEAD") {
        request_.version(11);
        request_.method_string(request.method);
        request_.target(request.target);
        for (const auto& [key, value] : px::sanitize(request.fields)) request_.insert(key, value);
        request_.body() = std::move(request.body);
        request_.keep_alive(false);
        request_.prepare_payload();
    }
    void start() {
        timer_.expires_after(timeout_);
        timer_.async_wait([self = shared_from_this()](Code error) { if (!error) self->fail(504); });
        socket_.async_connect(endpoint_, [self = shared_from_this()](Code error) {
            if (self->closed_) return;
            if (error) { self->fail(502); return; }
            http::async_write(self->socket_, self->request_, [self](Code write_error, std::size_t) {
                if (self->closed_) return;
                if (write_error) { self->fail(502); return; }
                self->read();
            });
        });
    }
    void cancel() { close(); }
private:
    void read() {
        parser_ = std::make_unique<http::response_parser<http::string_body>>();
        parser_->header_limit(static_cast<std::uint32_t>(px::max_headers));
        parser_->body_limit(px::max_body);
        if (head_) parser_->skip(true);
        http::async_read(socket_, buffer_, *parser_, [self = shared_from_this()](Code error, std::size_t) {
            if (self->closed_) return;
            if (error) { self->fail(502); return; }
            auto response = self->parser_->release();
            const auto status = response.result_int();
            if (status < 200) {
                if (status == 101 || ++self->interim_ > 4) { self->fail(502); return; }
                self->read(); return;
            }
            try {
                px::Fields fields;
                for (const auto& field : response.base()) fields.emplace_back(px::lower(field.name_string()), std::string(field.value()));
                px::Response result{self->id_, status, std::string(response.reason()),
                    px::sanitize(fields, self->head_ || status == 304), std::move(response.body())};
                // Reuse the wire validator before letting an upstream response enter the tunnel.
                (void)px::encode_response(result);
                self->complete(std::move(result));
            } catch (const Error&) { self->fail(502); }
        });
    }
    void fail(unsigned status) {
        if (closed_) return;
        auto response = px::error_response(id_, status);
        if (head_) {
            response.fields.emplace_back("content-length", std::to_string(response.body.size()));
            response.body.clear();
        }
        complete(std::move(response));
    }
    void complete(px::Response response) {
        if (closed_) return;
        close();
        auto done = std::move(done_);
        done(std::move(response));
    }
    void close() {
        if (closed_) return;
        closed_ = true;
        timer_.cancel();
        Code ignored;
        socket_.shutdown(tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
    }
    tcp::socket socket_;
    asio::steady_timer timer_;
    tcp::endpoint endpoint_;
    std::chrono::milliseconds timeout_;
    Completion done_;
    std::uint64_t id_;
    bool head_, closed_ = false;
    unsigned interim_ = 0;
    http::request<http::string_body> request_;
    std::unique_ptr<http::response_parser<http::string_body>> parser_;
    beast::flat_buffer buffer_{px::max_headers + 8192};
};
LocalHttp::LocalHttp(asio::io_context& context, const configuration::Service& service,
    protocol::proxy::Request request, std::chrono::milliseconds timeout, Completion done)
    : impl_(std::make_shared<Impl>(context, service, std::move(request), timeout, std::move(done))) {}
LocalHttp::~LocalHttp() = default;
void LocalHttp::start() { impl_->start(); }
void LocalHttp::cancel() { impl_->cancel(); }
} // namespace shadow::networking::detail
