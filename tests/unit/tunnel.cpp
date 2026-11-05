#include <catch2/catch_test_macros.hpp>
#include <shadow/core/error.hpp>
#include <shadow/protocol/tunnel.hpp>
#include <shadow/security/validation.hpp>

namespace wire = shadow::protocol::tunnel;
TEST_CASE("secure protocol round trips every implemented frame") {
    const auto session = std::string(32, 'a');
    const wire::Welcome welcome{session, std::chrono::milliseconds(1000), std::chrono::milliseconds(3000)};
    for (const auto& frame : {
        wire::Frame{wire::Type::hello, "home-server"}, wire::Frame{wire::Type::welcome, wire::encode_welcome(welcome)},
        wire::Frame{wire::Type::ping, wire::heartbeat_id(1)}, wire::Frame{wire::Type::pong, wire::heartbeat_id(1)},
        wire::Frame{wire::Type::goodbye, "shutdown"}}) {
        const auto encoded = wire::encode(frame);
        const auto decoded = wire::decode(encoded);
        CHECK(decoded.type == frame.type);
        CHECK(decoded.payload == frame.payload);
    }
    CHECK(wire::decode_welcome(wire::encode_welcome(welcome)).session_id == session);
    CHECK(wire::heartbeat_id(1) == "0000000000000001");
    CHECK(wire::heartbeat_id(0xffffffffffffffffULL) == "ffffffffffffffff");
}
TEST_CASE("secure framing rejects version flags length and malformed messages") {
    const auto valid = wire::encode({wire::Type::hello, "home-server"});
    for (const auto index : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) {
        auto bytes = valid;
        bytes[static_cast<std::size_t>(index)] = 255;
        CHECK_THROWS_AS(wire::decode(bytes), shadow::Error);
    }
    CHECK_THROWS_AS(wire::decode(std::span(valid).first(11)), shadow::Error);
    auto extra = valid; extra.push_back(0);
    CHECK_THROWS_AS(wire::decode(extra), shadow::Error);
    for (const auto& frame : {wire::Frame{wire::Type::hello, "bad\nname"}, wire::Frame{wire::Type::pong, "1"},
         wire::Frame{wire::Type::goodbye, "arbitrary"}, wire::Frame{wire::Type::welcome, "invalid"}})
        CHECK_THROWS_AS(wire::encode(frame), shadow::Error);
    for (const auto& suffix : {":99:3000", ":1000:60001", ":1000:3000:extra", ":-1:3000", ":1e3:3000", ":1000:"})
        CHECK_THROWS_AS(wire::decode_welcome(std::string(32, 'a') + suffix), shadow::Error);
    CHECK(shadow::security::valid_fingerprint(std::string(64, 'f')));
    CHECK_FALSE(shadow::security::valid_fingerprint(std::string(64, 'F')));
    CHECK_FALSE(shadow::security::valid_fingerprint(std::string(63, 'a')));
}
