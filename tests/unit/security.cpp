#include <catch2/catch_test_macros.hpp>
#include <shadow/security/policy.hpp>
#include <shadow/core/error.hpp>
#include <shadow/protocol/proxy.hpp>
#include <shadow/protocol/tunnel.hpp>
#include <random>
#include <shadow/observability/log.hpp>
#include <sstream>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <cmath>
namespace security = shadow::security;
namespace px = shadow::protocol::proxy;
namespace wire = shadow::protocol::tunnel;
TEST_CASE("HTTP authorization uses canonical segment boundaries and explicit methods") {
    const security::HttpPolicy policy{{"GET", "HEAD"}, {"/api", "/health"}};
    security::validate_policy(policy);
    for (auto path : {"/api", "/api/", "/api/v1?q=%2f", "/%61pi/items", "/health?token=ignored"}) CHECK(security::allowed(policy, "GET", path));
    for (auto path : {"/apix", "/API", "/private?path=/api", "*"}) CHECK_FALSE(security::allowed(policy, "GET", path));
    CHECK_FALSE(security::allowed(policy, "POST", "/api"));
    CHECK_FALSE(security::allowed(policy, "get", "/api"));
    CHECK_FALSE(security::allowed({}, "PROPFIND", "/"));
    for (auto path : {"//api", "/api/../private", "/api/%2e%2e/private", "/api/%2fprivate", "/api/%5cprivate", "/api/%252fprivate",
                      "/api\\private", "/api;x=/private", "/api/%00", "/api/%20", "/api/%zz", "/api/%", "/api/%c0%af", "/./api"}) {
        CHECK_THROWS_AS(security::canonical_path(path), shadow::Error);
        CHECK_THROWS_AS(px::validate_target("GET", path), shadow::Error);
    }
    for (const security::HttpPolicy& invalid : {security::HttpPolicy{{}, {"/"}}, {{"TRACE"}, {"/"}}, {{"GET", "GET"}, {"/"}},
            {{"get"}, {"/"}}, {{"GET"}, {"/api/"}}, {{"GET"}, {"/a?b"}}, {{"GET"}, {"/%61"}}, {{"GET"}, {"/", "/"}}})
        CHECK_THROWS_AS(security::validate_policy(invalid), shadow::Error);
}
TEST_CASE("runtime security logging bounds amplification under a burst") {
    std::ostringstream output;
    const auto started = std::chrono::steady_clock::now();
    auto* previous = std::clog.rdbuf(output.rdbuf());
    for (int i = 0; i < 5000; ++i) shadow::observability::log(shadow::observability::Level::warning, "gateway", "http_policy_denied");
    std::clog.rdbuf(previous);
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    const auto value = output.str();
    const auto lines = std::count(value.begin(), value.end(), '\n');
    CHECK(lines > 0);
    CHECK(static_cast<double>(lines) <= 401 + std::ceil(elapsed * 400));
}
TEST_CASE("bounded protocol mutation corpus rejects or exactly roundtrips without undefined state") {
    const px::Request request{17, "api", "POST", "/echo?q=1", {{"host", "api.example.test"}}, std::string("a\0z", 3)};
    const auto original = wire::encode({wire::Type::request, px::encode_request(request)});
    std::mt19937 random(20261116);
    for (unsigned i = 0; i < 5000; ++i) {
        auto bytes = original;
        bytes[random() % bytes.size()] ^= static_cast<std::uint8_t>(1U << (random() % 8));
        if (i % 3 == 0) bytes.resize(random() % bytes.size());
        try {
            const auto frame = wire::decode(bytes);
            CHECK(wire::encode(frame) == bytes);
            if (frame.type == wire::Type::request) {
                const auto decoded = px::decode_request(frame.payload);
                CHECK(px::encode_request(decoded) == frame.payload);
            }
        } catch (const shadow::Error&) { SUCCEED(); }
    }
}
