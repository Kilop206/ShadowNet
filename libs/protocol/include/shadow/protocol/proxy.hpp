#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace shadow::protocol::proxy {
inline constexpr std::size_t max_body = std::size_t{1024} * 1024;
inline constexpr std::size_t max_headers = 16384;
inline constexpr std::size_t max_fields = 64;
inline constexpr std::size_t max_packet = max_body + 32768;
using Fields = std::vector<std::pair<std::string, std::string>>;
struct Service { std::string name, hostname; bool operator==(const Service&) const = default; };
struct Request {
    std::uint64_t id = 0;
    std::string service, method, target;
    Fields fields;
    std::string body;
};
struct Response {
    std::uint64_t id = 0;
    unsigned status = 502;
    std::string reason;
    Fields fields;
    std::string body;
};
std::string encode_services(const std::vector<Service>& services);
std::vector<Service> decode_services(std::string_view bytes);
std::string encode_request(const Request& request);
Request decode_request(std::string_view bytes);
std::string encode_response(const Response& response);
Response decode_response(std::string_view bytes);
std::string encode_id(std::uint64_t id);
std::uint64_t decode_id(std::string_view bytes);
std::string lower(std::string_view value);
std::string hostname(std::string_view authority);
void validate_target(std::string_view method, std::string_view target);
std::string single_field(const Fields& fields, std::string_view name);
Fields sanitize(const Fields& fields, bool preserve_content_length = false);
Fields sanitize_request(const Fields& fields, std::string_view client_ip);
bool loops_to_gateway(const Fields& fields);
Response error_response(std::uint64_t id, unsigned status);
} // namespace shadow::protocol::proxy
