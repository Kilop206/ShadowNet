#include <catch2/catch_test_macros.hpp>
#include "proxy_router.hpp"
#include <shadow/protocol/proxy.hpp>

namespace wire = shadow::protocol::tunnel;
namespace px = shadow::protocol::proxy;
TEST_CASE("agent deferred replies obey cancellation and bounded backpressure deterministically") {
    boost::asio::io_context context;
    shadow::configuration::Agent config{};
    config.services.push_back({"api", "api.example.test", "127.0.0.1", 8080, {}});
    bool writable = false;
    std::vector<wire::Frame> output;
    auto proxy = std::make_shared<shadow::networking::detail::AgentProxy>(context, config,
        [&](const wire::Frame& frame) {
            if (frame.type == wire::Type::register_services) return true;
            if (!writable) return false;
            output.push_back(frame); return true;
        }, std::make_shared<shadow::BufferBudget>(std::size_t{64} * 1024 * 1024));
    proxy->start();
    REQUIRE(proxy->message({wire::Type::registered, px::encode_services({{"api", "api.example.test"}})}));
    const auto submit = [&](std::uint64_t id) {
        return proxy->message({wire::Type::request, px::encode_request({id, "unpublished", "GET", "/", {{"host", "api.example.test"}}, ""})});
    };
    SECTION("cancel while sender is blocked then resume without replay") {
        REQUIRE(submit(1));
        CHECK(output.empty());
        REQUIRE(proxy->message({wire::Type::cancel, px::encode_id(1)}));
        writable = true; proxy->writable();
        CHECK(output.empty());
        REQUIRE(submit(2));
        REQUIRE(output.size() == 1);
        CHECK(px::decode_response(output[0].payload).id == 2);
        CHECK(px::decode_response(output[0].payload).status == 404);
        writable = false;
        REQUIRE(submit(3));
        CHECK(output.size() == 1);
        writable = true; proxy->writable();
        REQUIRE(output.size() == 2);
        CHECK(px::decode_response(output[1].payload).id == 3);
        proxy->writable();
        CHECK(output.size() == 2);
    }
    SECTION("a peer cannot accumulate an unbounded queue of rejected requests") {
        for (std::uint64_t id = 1; id <= 128; ++id) REQUIRE(submit(id));
        CHECK_FALSE(submit(129));
        CHECK(output.empty());
    }
    proxy->stop();
}
