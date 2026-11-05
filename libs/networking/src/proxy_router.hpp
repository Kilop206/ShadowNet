#pragma once
#include "secure_session.hpp"
#include "https_server.hpp"
#include "local_http.hpp"
#include <boost/asio/steady_timer.hpp>
#include <map>
#include <deque>
#include <set>

namespace shadow::networking::detail {
class GatewayProxy : public std::enable_shared_from_this<GatewayProxy> {
public:
    GatewayProxy(boost::asio::io_context& context, configuration::Gateway config);
    bool message(const std::shared_ptr<SecureSession>& session, const protocol::tunnel::Frame& frame);
    CancelRequest dispatch(protocol::proxy::Request request, ProxyCompletion done);
    void disconnected(const std::shared_ptr<SecureSession>& session);
    void stop();
private:
    struct Route { std::string service; std::weak_ptr<SecureSession> session; };
    struct Pending {
        std::weak_ptr<SecureSession> session;
        ProxyCompletion done;
        std::shared_ptr<boost::asio::steady_timer> timer;
        bool head;
    };
    void cancel(std::uint64_t id);
    void complete(std::uint64_t id, protocol::proxy::Response response);
    boost::asio::io_context& context_;
    configuration::Gateway config_;
    configuration::Https limits_;
    std::map<std::string, Route> routes_;
    std::set<const SecureSession*> registered_;
    std::set<std::string> authorized_hosts_;
    std::map<std::uint64_t, Pending> pending_;
    std::uint64_t next_id_ = 0;
    double tokens_;
    std::chrono::steady_clock::time_point refill_ = std::chrono::steady_clock::now();
    bool stopped_ = false;
};
class AgentProxy : public std::enable_shared_from_this<AgentProxy> {
public:
    using Send = std::function<bool(const protocol::tunnel::Frame&)>;
    AgentProxy(boost::asio::io_context& context, configuration::Agent config, Send send, std::shared_ptr<BufferBudget> budget);
    void start();
    bool message(const protocol::tunnel::Frame& frame);
    void writable();
    void stop();
private:
    boost::asio::io_context& context_;
    configuration::Agent config_;
    Send send_;
    std::shared_ptr<BufferBudget> budget_;
    struct Work {
        std::shared_ptr<LocalHttp> local;
        std::shared_ptr<BufferBudget::Lease> reservation;
        std::optional<protocol::tunnel::Frame> response;
    };
    std::vector<protocol::proxy::Service> services_;
    std::map<std::uint64_t, Work> requests_;
    std::deque<std::uint64_t> responses_;
    std::uint64_t last_id_ = 0;
    bool registered_ = false, stopped_ = false, backpressured_ = false;
};
} // namespace shadow::networking::detail
