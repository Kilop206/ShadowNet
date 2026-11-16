#pragma once
#include <shadow/configuration/config.hpp>
#include <shadow/protocol/proxy.hpp>
#include <shadow/observability/metrics.hpp>
#include <boost/asio/io_context.hpp>
#include <functional>
#include <memory>

namespace shadow::networking::detail {
using ProxyCompletion = std::function<void(protocol::proxy::Response)>;
using CancelRequest = std::function<void()>;
using Dispatch = std::function<CancelRequest(protocol::proxy::Request, ProxyCompletion)>;
class HttpsServer {
public:
    HttpsServer(boost::asio::io_context& context, configuration::Https config, Dispatch dispatch, std::shared_ptr<observability::Metrics> metrics);
    ~HttpsServer();
    void start();
    void stop();
private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};
} // namespace shadow::networking::detail
