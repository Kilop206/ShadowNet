#pragma once
#include <shadow/protocol/proxy.hpp>
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace shadow::protocol::tunnel {
inline constexpr std::size_t control_message = 268;
inline constexpr std::size_t max_message = proxy::max_packet + 12;
inline constexpr const char* path = "/shadow/tunnel/v3";
inline constexpr const char* subprotocol = "shadownet.v3";
enum class Type : std::uint8_t {
    hello = 1, welcome = 2, ping = 3, pong = 4, goodbye = 5,
    register_services = 6, registered = 7, request = 8, response = 9, cancel = 10
};
struct Frame { Type type; std::string payload; };
struct Welcome {
    std::string session_id;
    std::chrono::milliseconds interval;
    std::chrono::milliseconds timeout;
};
std::vector<std::uint8_t> encode(const Frame& frame);
Frame decode(std::span<const std::uint8_t> bytes);
std::string encode_welcome(const Welcome& welcome);
Welcome decode_welcome(const std::string& payload);
std::string heartbeat_id(std::uint64_t sequence);
} // namespace shadow::protocol::tunnel
