#pragma once
#include <shadow/configuration/config.hpp>
#include <shadow/protocol/proxy.hpp>
#include <shadow/core/buffer_budget.hpp>
#include <boost/asio/io_context.hpp>
#include <functional>
#include <memory>

namespace shadow::networking::detail {
class LocalHttp {
public:
    using Completion = std::function<void(protocol::proxy::Response)>;
    LocalHttp(boost::asio::io_context& context, const configuration::Service& service,
        protocol::proxy::Request request, std::chrono::milliseconds timeout, Completion done, std::shared_ptr<BufferBudget::Lease> reservation);
    ~LocalHttp();
    void start();
    void cancel();
private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};
} // namespace shadow::networking::detail
