#pragma once
#include <shadow/configuration/config.hpp>
#include <shadow/observability/metrics.hpp>
#include <boost/asio/io_context.hpp>
#include <memory>
namespace shadow::networking::detail {
class MetricsServer {
public:
    MetricsServer(boost::asio::io_context& context, configuration::MetricsEndpoint config, std::shared_ptr<observability::Metrics> metrics);
    ~MetricsServer();
    void start();
    void stop();
private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};
} // namespace shadow::networking::detail
