#include <shadow/protocol/tunnel.hpp>
#include <shadow/core/error.hpp>
#include <shadow/security/validation.hpp>
#include <charconv>
#include <string_view>

namespace shadow::protocol::tunnel {
namespace {
bool hex(std::string_view text, std::size_t size) {
    if (text.size() != size) return false;
    for (char c : text) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
std::chrono::milliseconds duration(std::string_view value) {
    unsigned count = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), count);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || count < 100 || count > 60000)
        throw Error("invalid negotiated heartbeat");
    return std::chrono::milliseconds(count);
}
void validate(const Frame& frame) {
    switch (frame.type) {
    case Type::hello:
        if (!security::valid_identifier(frame.payload)) throw Error("invalid HELLO");
        break;
    case Type::welcome: (void)decode_welcome(frame.payload); break;
    case Type::ping: case Type::pong:
        if (!hex(frame.payload, 16)) throw Error("invalid heartbeat identifier");
        break;
    case Type::goodbye:
        if (frame.payload != "shutdown") throw Error("invalid goodbye reason");
        break;
    default: throw Error("unsupported tunnel message type");
    }
}
}
std::string encode_welcome(const Welcome& welcome) {
    const auto result = welcome.session_id + ":" + std::to_string(welcome.interval.count()) + ":" + std::to_string(welcome.timeout.count());
    (void)decode_welcome(result);
    return result;
}
Welcome decode_welcome(const std::string& payload) {
    const auto first = payload.find(':');
    const auto second = payload.find(':', first == std::string::npos ? first : first + 1);
    if (first != 32 || second == std::string::npos || !hex(std::string_view(payload).substr(0, first), 32))
        throw Error("invalid WELCOME");
    return {payload.substr(0, first), duration(std::string_view(payload).substr(first + 1, second - first - 1)),
        duration(std::string_view(payload).substr(second + 1))};
}
std::vector<std::uint8_t> encode(const Frame& frame) {
    validate(frame);
    if (frame.payload.empty() || frame.payload.size() > 256) throw Error("invalid tunnel payload length");
    const auto size = static_cast<std::uint32_t>(frame.payload.size());
    std::vector<std::uint8_t> bytes{'S','H','D','W', 2, static_cast<std::uint8_t>(frame.type), 0, 0,
        static_cast<std::uint8_t>(size >> 24U), static_cast<std::uint8_t>(size >> 16U),
        static_cast<std::uint8_t>(size >> 8U), static_cast<std::uint8_t>(size)};
    bytes.insert(bytes.end(), frame.payload.begin(), frame.payload.end());
    return bytes;
}
Frame decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 12 || bytes.size() > max_message || bytes[0] != 'S' || bytes[1] != 'H' || bytes[2] != 'D' || bytes[3] != 'W' ||
        bytes[4] != 2 || bytes[6] != 0 || bytes[7] != 0) throw Error("invalid tunnel frame header");
    std::uint32_t size = 0;
    for (std::size_t i = 8; i < 12; ++i) size = (size << 8U) | bytes[i];
    if (size == 0 || size > 256 || bytes.size() != 12 + size) throw Error("invalid tunnel frame length");
    Frame frame{static_cast<Type>(bytes[5]), std::string(bytes.begin() + 12, bytes.end())};
    validate(frame);
    return frame;
}
std::string heartbeat_id(std::uint64_t sequence) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(16, '0');
    for (std::size_t i = 0; i < 16; ++i) { result[15 - i] = digits[sequence & 15U]; sequence >>= 4U; }
    return result;
}
} // namespace shadow::protocol::tunnel
