#pragma once
#include <shadow/security/tls.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <string>

namespace shadow::networking::detail {
struct SessionOptions {
    bool server = false;
    std::string name;
    std::chrono::milliseconds timeout{3000};
    std::chrono::milliseconds interval{1000};
    std::chrono::milliseconds pong_timeout{3000};
    std::function<std::string(const std::string&)> authorize;
    std::function<bool(const std::string&)> claim;
    std::function<void()> ready;
    std::function<void(const std::string&)> done;
};
class SecureSession {
public:
    SecureSession(boost::asio::ip::tcp::socket socket, std::shared_ptr<boost::asio::ssl::context> tls, SessionOptions options);
    ~SecureSession();
    void accept();
    void connect(const std::string& host, std::uint16_t port);
    void stop();
    const std::string& name() const;
    bool claimed() const;
private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};
} // namespace shadow::networking::detail
