#include <shadow/protocol/message.hpp>
#include <shadow/core/error.hpp>
#include <shadow/security/validation.hpp>
#include <algorithm>

namespace shadow::protocol {
namespace {
bool valid_type(Type type) { return type == Type::hello || type == Type::hello_ack; }
}
Header decode_header(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != header_size) throw Error("invalid frame header length");
    if (bytes[0] != 'S' || bytes[1] != 'H' || bytes[2] != 'D' || bytes[3] != 'W') throw Error("invalid frame magic");
    if (bytes[4] != version) throw Error("unsupported protocol version");
    const auto type = static_cast<Type>(bytes[5]);
    if (!valid_type(type) || bytes[6] != 0 || bytes[7] != 0) throw Error("invalid frame flags or type");
    std::uint32_t size = 0;
    for (std::size_t i = 8; i < 12; ++i) size = (size << 8U) | bytes[i];
    if (size == 0 || size > max_payload) throw Error("frame payload limit exceeded");
    return {type, size};
}
Message decode_payload(Header header, std::span<const std::uint8_t> bytes) {
    if (!valid_type(header.type) || header.payload_size == 0 || header.payload_size > max_payload || bytes.size() != header.payload_size)
        throw Error("invalid payload length or type");
    std::string name(bytes.begin(), bytes.end());
    if (!security::valid_identifier(name)) throw Error("invalid agent identifier");
    return {header.type, std::move(name)};
}
std::vector<std::uint8_t> encode(const Message& message) {
    if (!valid_type(message.type) || !security::valid_identifier(message.name)) throw Error("invalid handshake message");
    const auto size = static_cast<std::uint32_t>(message.name.size());
    std::vector<std::uint8_t> bytes{'S','H','D','W', version, static_cast<std::uint8_t>(message.type), 0, 0,
        static_cast<std::uint8_t>(size >> 24U), static_cast<std::uint8_t>(size >> 16U),
        static_cast<std::uint8_t>(size >> 8U), static_cast<std::uint8_t>(size)};
    bytes.insert(bytes.end(), message.name.begin(), message.name.end());
    return bytes;
}
} // namespace shadow::protocol
