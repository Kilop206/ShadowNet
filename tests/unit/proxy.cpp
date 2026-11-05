#include <catch2/catch_test_macros.hpp>
#include <shadow/protocol/proxy.hpp>
#include <shadow/protocol/tunnel.hpp>
#include <shadow/core/error.hpp>

namespace px = shadow::protocol::proxy;
namespace wire = shadow::protocol::tunnel;
namespace {
px::Request request() { return {1, "api", "POST", "/echo?q=1", {{"host", "api.example.test"}, {"content-type", "application/octet-stream"}}, std::string("a\0\xffz", 4)}; }
}
TEST_CASE("proxy packets preserve binary bodies duplicate headers and request correlation") {
    const auto value = request();
    const auto decoded = px::decode_request(px::encode_request(value));
    CHECK(decoded.id == 1);
    CHECK(decoded.service == "api");
    CHECK(decoded.method == "POST");
    CHECK(decoded.target == "/echo?q=1");
    CHECK(decoded.body == value.body);
    CHECK(decoded.fields == value.fields);
    px::Response response{42, 201, "Created Here", {{"set-cookie", "a=1"}, {"set-cookie", "b=2"}}, value.body};
    const auto reply = px::decode_response(px::encode_response(response));
    CHECK(reply.id == 42);
    CHECK(reply.status == 201);
    CHECK(reply.reason == "Created Here");
    CHECK(reply.fields == response.fields);
    CHECK(reply.body == value.body);
    const auto framed = wire::encode({wire::Type::request, px::encode_request(value)});
    CHECK(framed[4] == 3);
    CHECK(px::decode_request(wire::decode(framed).payload).body == value.body);
    CHECK(px::decode_id(px::encode_id(0xffffffffffffffffULL)) == 0xffffffffffffffffULL);
    CHECK_THROWS_AS(px::encode_id(0), shadow::Error);
    CHECK_THROWS_AS(px::decode_id(std::string(7, 'a')), shadow::Error);
}
TEST_CASE("service registration only contains unique validated identifiers and hostnames") {
    const std::vector<px::Service> services{{"api", "api.example.test"}, {"website", "app.example.test"}};
    CHECK(px::decode_services(px::encode_services(services)) == services);
    CHECK(px::decode_services(px::encode_services({})).empty());
    CHECK_THROWS_AS(px::encode_services({{"api", "api.test"}, {"api", "app.test"}}), shadow::Error);
    CHECK_THROWS_AS(px::encode_services({{"api", "api.test"}, {"website", "api.test"}}), shadow::Error);
    CHECK_THROWS_AS(px::encode_services({{"api", "http://internal/"}}), shadow::Error);
    CHECK_THROWS_AS(px::encode_services(std::vector<px::Service>(33)), shadow::Error);
    CHECK_THROWS_AS(px::decode_services(std::string("\xff\xff", 2)), shadow::Error);
}
TEST_CASE("proxy packets reject truncation oversized fields and ambiguous destinations") {
    const auto encoded = px::encode_request(request());
    for (std::size_t size = 0; size < encoded.size(); ++size)
        CHECK_THROWS_AS(px::decode_request(std::string_view(encoded).substr(0, size)), shadow::Error);
    CHECK_THROWS_AS(px::decode_request(encoded + "extra"), shadow::Error);
    auto large = request(); large.body.assign(px::max_body, 'x');
    CHECK(px::decode_request(px::encode_request(large)).body.size() == px::max_body);
    large.body += 'x';
    CHECK_THROWS_AS(px::encode_request(large), shadow::Error);
    for (const auto& method : {"CONNECT", "TRACE", "bad method", "GET\r\n"}) {
        auto value = request(); value.method = method;
        CHECK_THROWS_AS(px::encode_request(value), shadow::Error);
    }
    for (const auto& target : {"http://169.254.169.254/", "*", "/path#fragment", "/path\nInjected"}) {
        auto value = request(); value.target = target;
        CHECK_THROWS_AS(px::encode_request(value), shadow::Error);
    }
    auto value = request(); value.fields.emplace_back("host", "another.example.test");
    CHECK_THROWS_AS(px::encode_request(value), shadow::Error);
    value = request(); value.fields.emplace_back("x-evil", "value\r\nInjected: yes");
    CHECK_THROWS_AS(px::encode_request(value), shadow::Error);
    value = request(); value.fields.emplace_back("x-large", std::string(8193, 'x'));
    CHECK_THROWS_AS(px::encode_request(value), shadow::Error);
    CHECK(px::hostname("API.Example.Test:8443") == "api.example.test");
    for (const auto& host : {"api.test:0", "api.test:65536", "api.test:abc", "api.test:", "api.test:80:90", "api.test/", " api.test"})
        CHECK_THROWS_AS(px::hostname(host), shadow::Error);
}
TEST_CASE("HTTP sanitization removes named connection fields and untrusted proxy metadata") {
    px::Fields fields{{"Host", "api.example.test"}, {"Connection", "keep-alive, X-Internal"}, {"X-Internal", "secret"},
        {"Transfer-Encoding", "chunked"}, {"Content-Length", "999"}, {"Forwarded", "for=spoof"},
        {"X-Forwarded-For", "spoof"}, {"X-Forwarded-Proto", "http"}, {"X-Real-IP", "spoof"},
        {"Authorization", "Bearer test-only"}, {"Cookie", "session=test"}};
    const auto result = px::sanitize_request(fields, "203.0.113.5");
    CHECK(px::single_field(result, "x-internal").empty());
    CHECK(px::single_field(result, "content-length").empty());
    CHECK(px::single_field(result, "transfer-encoding").empty());
    CHECK(px::single_field(result, "forwarded").empty());
    CHECK(px::single_field(result, "x-forwarded-for") == "203.0.113.5");
    CHECK(px::single_field(result, "x-forwarded-proto") == "https");
    CHECK(px::single_field(result, "via") == "1.1 shadownet");
    CHECK(px::loops_to_gateway({{"via", "1.0 external, 1.1 shadownet"}}));
    CHECK_FALSE(px::loops_to_gateway({{"via", "1.1 external"}}));
    CHECK(px::single_field(result, "authorization") == "Bearer test-only");
    CHECK(px::single_field(result, "cookie") == "session=test");
    CHECK_THROWS_AS(px::sanitize({{"connection", "Host"}, {"host", "api.test"}}), shadow::Error);
    CHECK_THROWS_AS(px::sanitize({{"connection", "Content-Length"}}), shadow::Error);
    CHECK(px::sanitize({{"content-length", "5"}}, true).size() == 1);
    CHECK_THROWS_AS(px::encode_response({1, 101, "Switching Protocols", {}, ""}), shadow::Error);
    CHECK_THROWS_AS(px::encode_response({1, 200, "OK\r\nInjected", {}, ""}), shadow::Error);
    CHECK_THROWS_AS(px::encode_response({1, 204, "No Content", {}, "body"}), shadow::Error);
    CHECK_THROWS_AS(px::encode_response({1, 200, "OK", {{"content-length", "bad"}}, ""}), shadow::Error);
}
