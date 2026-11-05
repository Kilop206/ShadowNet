#include <shadow/protocol/proxy.hpp>
#include <shadow/core/error.hpp>
#include <shadow/security/validation.hpp>
#include <charconv>
#include <set>
#include <limits>

namespace shadow::protocol::proxy {
namespace {
void require(bool valid) { if (!valid) throw Error("invalid proxy message"); }
bool token(std::string_view value) {
    if (value.empty()) return false;
    for (char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) continue;
        if (std::string_view("!#$%&'*+-.^_`|~").find(c) == std::string_view::npos) return false;
    }
    return true;
}
bool field_value(std::string_view value) {
    for (const auto c : value) {
        const auto byte = static_cast<unsigned char>(c);
        if ((byte < 32 && byte != 9) || byte == 127) return false;
    }
    return true;
}
void validate_fields(const Fields& fields) {
    require(fields.size() <= max_fields);
    std::size_t size = 0;
    for (const auto& [key, value] : fields) {
        require(key.size() <= 128 && token(key) && key == lower(key) && value.size() <= 8192 && field_value(value));
        size += key.size() + value.size() + 4;
    }
    require(size <= max_headers);
}
template<unsigned Width>
void integer(std::string& bytes, std::uint64_t value) {
    for (unsigned i = Width; i > 0; --i) bytes += static_cast<char>((value >> ((i - 1) * 8U)) & 255U);
}
void text(std::string& bytes, std::string_view value) {
    require(value.size() <= 65535);
    integer<2>(bytes, value.size()); bytes.append(value);
}
void fields(std::string& bytes, const Fields& values) {
    validate_fields(values);
    integer<2>(bytes, values.size());
    for (const auto& [key, value] : values) { text(bytes, key); text(bytes, value); }
}
void body(std::string& bytes, std::string_view value) {
    require(value.size() <= max_body);
    integer<4>(bytes, value.size()); bytes.append(value);
    require(bytes.size() <= max_packet);
}
class Reader {
public:
    explicit Reader(std::string_view bytes) : bytes_(bytes) { require(bytes.size() <= max_packet); }
    std::uint64_t integer(unsigned width) {
        require(bytes_.size() >= width);
        std::uint64_t value = 0;
        for (unsigned i = 0; i < width; ++i) value = (value << 8U) | static_cast<unsigned char>(bytes_[i]);
        bytes_.remove_prefix(width); return value;
    }
    std::string text(std::size_t limit) { return take(integer(2), limit); }
    Fields fields() {
        const auto count = integer(2);
        require(count <= max_fields);
        Fields result;
        for (std::size_t i = 0; i < count; ++i) {
            auto key = text(128); auto value = text(8192);
            result.emplace_back(std::move(key), std::move(value));
        }
        validate_fields(result); return result;
    }
    std::string body() { return take(integer(4), max_body); }
    void done() const { require(bytes_.empty()); }
private:
    std::string take(std::uint64_t length, std::size_t limit) {
        require(length <= limit && length <= bytes_.size());
        auto value = std::string(bytes_.substr(0, static_cast<std::size_t>(length)));
        bytes_.remove_prefix(static_cast<std::size_t>(length)); return value;
    }
    std::string_view bytes_;
};
void request(const Request& value) {
    require(value.id != 0 && security::valid_identifier(value.service));
    validate_target(value.method, value.target);
    validate_fields(value.fields);
    (void)hostname(single_field(value.fields, "host"));
    require(value.body.size() <= max_body);
}
void response(const Response& value) {
    require(value.id != 0 && value.status >= 200 && value.status <= 599 && value.reason.size() <= 128);
    for (const auto c : value.reason) require(c >= 32 && static_cast<unsigned char>(c) < 127);
    validate_fields(value.fields);
    require(value.body.size() <= max_body && ((value.status != 204 && value.status != 304) || value.body.empty()));
    const auto length = single_field(value.fields, "content-length");
    if (!length.empty()) {
        std::uint64_t parsed = 0;
        const auto result = std::from_chars(length.data(), length.data() + length.size(), parsed);
        require(result.ec == std::errc{} && result.ptr == length.data() + length.size());
    }
}
}
std::string lower(std::string_view value) {
    std::string result(value);
    for (auto& c : result) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return result;
}
void validate_target(std::string_view method, std::string_view target) {
    require(method.size() <= 32 && token(method) && method != "CONNECT" && method != "TRACE");
    require(!target.empty() && target.size() <= 8192 && (target.front() == '/' || (method == "OPTIONS" && target == "*")));
    for (const auto c : target) require(c > 32 && static_cast<unsigned char>(c) < 127 && c != '#');
}
std::string hostname(std::string_view authority) {
    const auto colon = authority.find(':');
    const auto name = lower(authority.substr(0, colon));
    require(security::valid_hostname(name));
    if (colon != std::string_view::npos) {
        const auto port = authority.substr(colon + 1);
        unsigned value = 0;
        const auto parsed = std::from_chars(port.data(), port.data() + port.size(), value);
        require(!port.empty() && parsed.ec == std::errc{} && parsed.ptr == port.data() + port.size() && value >= 1 && value <= 65535);
    }
    return name;
}
std::string single_field(const Fields& values, std::string_view name) {
    std::string result;
    bool found = false;
    for (const auto& [key, value] : values) if (lower(key) == name) {
        require(!found); found = true; result = value;
    }
    return result;
}
Fields sanitize(const Fields& input, bool preserve_content_length) {
    Fields normalized;
    for (const auto& [key, value] : input) normalized.emplace_back(lower(key), value);
    validate_fields(normalized);
    for (const auto& [key, value] : normalized) if (key == "transfer-encoding") {
        (void)value;
        const auto coding = single_field(normalized, "transfer-encoding");
        std::string_view trimmed(coding);
        while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t')) trimmed.remove_prefix(1);
        while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t')) trimmed.remove_suffix(1);
        // Beast removes chunk framing, but does not decode arbitrary transfer codings.
        require(lower(trimmed) == "chunked");
    }
    std::set<std::string> removed{"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
        "te", "trailer", "transfer-encoding", "upgrade"};
    if (!preserve_content_length) removed.insert("content-length");
    for (const auto& [key, value] : normalized) if (key == "connection") {
        std::string_view remaining(value);
        while (!remaining.empty()) {
            const auto comma = remaining.find(',');
            auto item = remaining.substr(0, comma);
            while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1);
            while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.remove_suffix(1);
            require(token(item));
            const auto name = lower(item);
            require(name != "host" && name != "content-length" && name != "transfer-encoding");
            removed.insert(name);
            if (comma == std::string_view::npos) break;
            remaining.remove_prefix(comma + 1);
        }
    }
    Fields result;
    for (auto& entry : normalized) if (!removed.contains(entry.first)) result.push_back(std::move(entry));
    return result;
}
Fields sanitize_request(const Fields& values, std::string_view client_ip) {
    const auto authority = single_field(values, "host");
    (void)hostname(authority);
    Fields result;
    for (auto& field : sanitize(values)) {
        const auto& key = field.first;
        if (key == "forwarded" || key.starts_with("x-forwarded-") || key == "x-real-ip" || key == "via" || key == "expect") continue;
        result.push_back(std::move(field));
    }
    result.emplace_back("x-forwarded-proto", "https");
    result.emplace_back("x-forwarded-host", authority);
    result.emplace_back("x-forwarded-for", client_ip);
    result.emplace_back("via", "1.1 shadownet");
    validate_fields(result);
    return result;
}
bool loops_to_gateway(const Fields& fields) {
    for (const auto& [key, value] : fields) if (lower(key) == "via") {
        std::string_view remaining(value);
        while (!remaining.empty()) {
            const auto comma = remaining.find(',');
            auto item = remaining.substr(0, comma);
            const auto protocol_end = item.find_first_of(" \t");
            if (protocol_end != std::string_view::npos) {
                item.remove_prefix(protocol_end);
                while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1);
                if (lower(item.substr(0, item.find_first_of(" \t("))) == "shadownet") return true;
            }
            if (comma == std::string_view::npos) break;
            remaining.remove_prefix(comma + 1);
            while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t')) remaining.remove_prefix(1);
        }
    }
    return false;
}
std::string encode_services(const std::vector<Service>& services) {
    require(services.size() <= 32);
    std::string result; integer<2>(result, services.size());
    std::set<std::string> names, hosts;
    for (const auto& service : services) {
        require(security::valid_identifier(service.name) && security::valid_hostname(service.hostname));
        require(names.insert(service.name).second && hosts.insert(service.hostname).second);
        text(result, service.name); text(result, service.hostname);
    }
    return result;
}
std::vector<Service> decode_services(std::string_view bytes) {
    Reader reader(bytes); const auto count = reader.integer(2); require(count <= 32);
    std::vector<Service> result;
    for (std::size_t i = 0; i < count; ++i) {
        auto name = reader.text(64); auto host = reader.text(253); result.push_back({std::move(name), std::move(host)});
    }
    reader.done(); (void)encode_services(result); return result;
}
std::string encode_request(const Request& value) {
    request(value); std::string result; integer<8>(result, value.id);
    text(result, value.service); text(result, value.method); text(result, value.target); fields(result, value.fields); body(result, value.body);
    return result;
}
Request decode_request(std::string_view bytes) {
    Reader reader(bytes); Request value; value.id = reader.integer(8);
    value.service = reader.text(64); value.method = reader.text(32); value.target = reader.text(8192);
    value.fields = reader.fields(); value.body = reader.body(); reader.done(); request(value); return value;
}
std::string encode_response(const Response& value) {
    response(value); std::string result; integer<8>(result, value.id); integer<2>(result, value.status);
    text(result, value.reason); fields(result, value.fields); body(result, value.body); return result;
}
Response decode_response(std::string_view bytes) {
    Reader reader(bytes); Response value; value.id = reader.integer(8); value.status = static_cast<unsigned>(reader.integer(2));
    value.reason = reader.text(128); value.fields = reader.fields(); value.body = reader.body(); reader.done(); response(value); return value;
}
std::string encode_id(std::uint64_t id) { require(id != 0); std::string value; integer<8>(value, id); return value; }
std::uint64_t decode_id(std::string_view bytes) { Reader reader(bytes); const auto id = reader.integer(8); reader.done(); require(id != 0); return id; }
Response error_response(std::uint64_t id, unsigned status) {
    const char* reason = "Bad Gateway";
    switch (status) {
    case 400: reason = "Bad Request"; break; case 404: reason = "Not Found"; break;
    case 403: reason = "Forbidden"; break;
    case 405: reason = "Method Not Allowed"; break; case 413: reason = "Content Too Large"; break;
    case 417: reason = "Expectation Failed"; break; case 429: reason = "Too Many Requests"; break;
    case 431: reason = "Request Header Fields Too Large"; break; case 501: reason = "Not Implemented"; break;
    case 503: reason = "Service Unavailable"; break; case 504: reason = "Gateway Timeout"; break;
    case 505: reason = "HTTP Version Not Supported"; break; default: break;
    case 508: reason = "Loop Detected"; break;
    }
    return {id, status, reason, {{"content-type", "text/plain; charset=utf-8"}}, std::string(reason) + "\n"};
}
} // namespace shadow::protocol::proxy
