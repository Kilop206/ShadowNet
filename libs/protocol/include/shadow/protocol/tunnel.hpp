#pragma once
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace shadow::protocol::tunnel {
inline constexpr std::size_t max_message = 268;
inline constexpr const char* path = "/shadow/tunnel/v2";
inline constexpr const char* subprotocol = "shadownet.v2";
enum class Type : std::uint8_t { hello = 1, welcome = 2, ping = 3, pong = 4, goodbye = 5 };
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
