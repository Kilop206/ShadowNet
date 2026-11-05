#include <catch2/catch_test_macros.hpp>
#include <shadow/core/buffer_budget.hpp>
#include <shadow/protocol/outbox.hpp>
#include <limits>

namespace wire = shadow::protocol::tunnel;
TEST_CASE("buffer reservations survive owners and account cancelled I/O until last release") {
    shadow::BufferBudget budget(100);
    unsigned notifications = 0;
    budget.on_release([&] { ++notifications; });
    auto first = budget.acquire(60);
    auto retained = first;
    REQUIRE(first);
    CHECK_FALSE(budget.acquire(41));
    CHECK_FALSE(budget.acquire(std::numeric_limits<std::size_t>::max()));
    CHECK_FALSE(budget.acquire(0));
    first.reset();
    CHECK(budget.used() == 60);
    CHECK(notifications == 0);
    auto second = budget.acquire(40);
    CHECK(budget.used() == 100);
    CHECK(budget.peak() == 100);
    retained.reset();
    CHECK(budget.used() == 40);
    CHECK(notifications == 1);
    CHECK(budget.acquire(60));
    second.reset();
    CHECK(budget.used() == 0);
    CHECK(budget.peak() == 100);
    budget.on_release({});
}
TEST_CASE("outbox reserves control capacity and does not invalidate an active buffer") {
    wire::Outbox outbox;
    const wire::Frame data{wire::Type::response, std::string(wire::max_message - 12, 'x')};
    for (int i = 0; i < 4; ++i) REQUIRE(outbox.push(data));
    CHECK_FALSE(outbox.push(data));
    const auto active = outbox.front();
    REQUIRE(outbox.push({wire::Type::ping, wire::heartbeat_id(1)}));
    REQUIRE(outbox.push({wire::Type::pong, wire::heartbeat_id(1)}));
    CHECK(outbox.front() == active);
    outbox.pop();
    CHECK(wire::decode(*outbox.front()).type == wire::Type::ping);
    outbox.pop();
    CHECK(wire::decode(*outbox.front()).type == wire::Type::pong);
    outbox.pop();
    CHECK(outbox.push(data));
    CHECK(outbox.data_bytes() == wire::Outbox::data_limit);
    outbox.clear();
    CHECK(outbox.empty());
    CHECK(active->size() == wire::max_message);
    for (int i = 0; i < 56; ++i) REQUIRE(outbox.push({wire::Type::response, "x"}));
    CHECK_FALSE(outbox.push({wire::Type::response, "x"}));
    for (int i = 0; i < 8; ++i) REQUIRE(outbox.push({wire::Type::pong, wire::heartbeat_id(1)}));
    CHECK_FALSE(outbox.push({wire::Type::pong, wire::heartbeat_id(1)}));
    outbox.clear();
    REQUIRE(outbox.push({wire::Type::request, "x"}));
    REQUIRE(outbox.push({wire::Type::cancel, shadow::protocol::proxy::encode_id(9)}));
    CHECK(wire::decode(*outbox.front()).type == wire::Type::request);
    outbox.pop();
    CHECK(wire::decode(*outbox.front()).type == wire::Type::cancel);
}
