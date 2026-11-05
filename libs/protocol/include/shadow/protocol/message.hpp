#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace shadow::protocol {
inline constexpr std::size_t header_size = 12;
inline constexpr std::size_t max_payload = 256;
inline constexpr std::uint8_t version = 1;
enum class Type : std::uint8_t { hello = 1, hello_ack = 2 };
struct Header { Type type; std::uint32_t payload_size; };
struct Message { Type type; std::string name; };
Header decode_header(std::span<const std::uint8_t> bytes);
Message decode_payload(Header header, std::span<const std::uint8_t> bytes);
std::vector<std::uint8_t> encode(const Message& message);
} // namespace shadow::protocol
