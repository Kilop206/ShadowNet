#include <shadow/configuration/config.hpp>
#include <shadow/core/error.hpp>
#include <shadow/security/validation.hpp>
#include <yaml-cpp/yaml.h>
#include <boost/asio/ip/address.hpp>
#include <array>
#include <fstream>
#include <initializer_list>
#include <set>
#include <string_view>

namespace shadow::configuration {
namespace {
constexpr std::size_t max_config_size = 65536;
void keys(const YAML::Node& node, std::initializer_list<std::string_view> allowed) {
    if (!node.IsMap()) throw Error("configuration section must be a mapping");
    std::set<std::string> seen;
    for (const auto& entry : node) {
        if (!entry.first.IsScalar()) throw Error("configuration keys must be scalars");
        const auto key = entry.first.as<std::string>();
        if (!seen.insert(key).second) throw Error("duplicate configuration key");
        bool recognized = false;
        for (auto candidate : allowed) if (key == candidate) recognized = true;
        if (!recognized) throw Error("unknown configuration key");
    }
}
std::string scalar(const YAML::Node& node, const char* key) {
    const auto value = node[key];
    if (!value || !value.IsScalar()) throw Error(std::string("missing or invalid field: ") + key);
    const auto result = value.as<std::string>();
    if (result.empty() || result.size() > 1024 || result.find('\0') != std::string::npos)
        throw Error(std::string("invalid field length: ") + key);
    return result;
}
struct Range { unsigned min; unsigned max; };
unsigned number(const YAML::Node& node, const char* key, Range range) {
    const auto text = scalar(node, key);
    unsigned value = 0;
    for (char c : text) {
        if (c < '0' || c > '9' || value > range.max / 10U) throw Error(std::string("invalid integer: ") + key);
        value = value * 10U + static_cast<unsigned>(c - '0');
        if (value > range.max) throw Error(std::string("integer out of range: ") + key);
    }
    if (value < range.min) throw Error(std::string("integer out of range: ") + key);
    return value;
}
YAML::Node document(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw Error("cannot open configuration file");
    std::array<char, max_config_size + 1> buffer{};
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    if (input.bad()) throw Error("cannot read configuration file");
    const auto size = static_cast<std::size_t>(input.gcount());
    if (size > max_config_size) throw Error("configuration exceeds 64 KiB");
    const auto documents = YAML::LoadAll(std::string(buffer.data(), size));
    if (documents.size() != 1) throw Error("expected one YAML document");
    return documents.front();
}
Transport transport(const YAML::Node& root) {
    const auto value = scalar(root, "transport");
    if (value == "local_tcp") return Transport::local_tcp;
    if (value == "wss") return Transport::wss;
    throw Error("unsupported transport");
}
void loopback(const std::string& host) {
    if (!security::is_loopback(host)) throw Error("milestone 1 requires literal 127.0.0.1 or ::1");
}
bool boolean(const YAML::Node& node, const char* key) {
    const auto value = scalar(node, key);
    if (value == "true") return true;
    if (value == "false") return false;
    throw Error("expected true or false");
}
bool ip_address(const std::string& value) {
    boost::system::error_code error;
    (void)boost::asio::ip::make_address(value, error);
    return !error;
}
security::TlsFiles tls_files(const YAML::Node& node, const std::filesystem::path& config_path, bool mutual = true) {
    if (mutual) keys(node, {"ca_file", "certificate_file", "private_key_file"});
    else keys(node, {"certificate_file", "private_key_file"});
    const auto resolve = [&](const char* key) {
        auto path = std::filesystem::path(scalar(node, key));
        if (path.is_relative()) path = config_path.parent_path() / path;
        std::error_code error;
        if (!std::filesystem::is_regular_file(path, error) || error) throw Error("TLS file is not a readable regular file");
        const auto size = std::filesystem::file_size(path, error);
        if (error || size == 0 || size > 1048576) throw Error("TLS file exceeds size bounds");
        std::ifstream input(path, std::ios::binary);
        if (!input) throw Error("TLS file is not readable");
        return path;
    };
    security::TlsFiles result{mutual ? resolve("ca_file") : std::filesystem::path{}, resolve("certificate_file"), resolve("private_key_file")};
#ifndef _WIN32
    const auto permissions = std::filesystem::status(result.private_key_file).permissions();
    constexpr auto forbidden = std::filesystem::perms::group_all | std::filesystem::perms::others_all;
    if ((permissions & forbidden) != std::filesystem::perms::none) throw Error("private key permissions must be 0600 or stricter");
#endif
    return result;
}
}
Agent load_agent(const std::filesystem::path& path) {
    try {
        const auto root = document(path);
        const auto mode = transport(root);
        if (mode == Transport::local_tcp) keys(root, {"transport", "agent", "services"});
        else keys(root, {"transport", "agent", "services", "security"});
        const auto node = root["agent"];
        if (mode == Transport::local_tcp) keys(node, {"name", "gateway_host", "port", "timeout_ms"});
        else keys(node, {"name", "gateway_host", "port", "timeout_ms", "reconnect", "max_in_flight", "backend_timeout_ms", "buffer_budget_bytes", "write_timeout_ms"});
        Agent result;
        result.name = scalar(node, "name");
        result.gateway_host = scalar(node, "gateway_host");
        result.port = static_cast<std::uint16_t>(number(node, "port", {.min = 1, .max = 65535}));
        result.timeout = std::chrono::milliseconds(number(node, "timeout_ms", {.min = 100, .max = 60000}));
        result.transport = mode;
        if (!security::valid_identifier(result.name)) throw Error("invalid agent name");
        if (mode == Transport::local_tcp) loopback(result.gateway_host);
        else {
            if (!ip_address(result.gateway_host) && !security::valid_hostname(result.gateway_host)) throw Error("invalid gateway hostname");
            result.tls = tls_files(root["security"], path);
            if (node["max_in_flight"]) result.max_in_flight = number(node, "max_in_flight", {.min = 1, .max = 64});
            if (node["backend_timeout_ms"]) result.backend_timeout = std::chrono::milliseconds(number(node, "backend_timeout_ms", {.min = 100, .max = 60000}));
            if (node["buffer_budget_bytes"]) result.buffer_budget_bytes = number(node, "buffer_budget_bytes", {.min = 8 * 1024 * 1024, .max = 1024 * 1024 * 1024});
            if (node["write_timeout_ms"]) result.write_timeout = std::chrono::milliseconds(number(node, "write_timeout_ms", {.min = 100, .max = 60000}));
            const auto reconnect = node["reconnect"];
            keys(reconnect, {"enabled", "initial_ms", "max_ms"});
            result.reconnect.enabled = boolean(reconnect, "enabled");
            result.reconnect.initial = std::chrono::milliseconds(number(reconnect, "initial_ms", {.min = 100, .max = 60000}));
            result.reconnect.maximum = std::chrono::milliseconds(number(reconnect, "max_ms", {.min = 100, .max = 300000}));
            if (result.reconnect.maximum < result.reconnect.initial) throw Error("reconnect max_ms is smaller than initial_ms");
        }
        const auto services = root["services"];
        if (services) {
            if (!services.IsSequence() || services.size() > 32) throw Error("services must be a sequence of at most 32 entries");
            std::set<std::string> names, hostnames;
            for (const auto& service : services) {
                keys(service, {"name", "hostname", "local_host", "local_port"});
                Service value{scalar(service, "name"), scalar(service, "hostname"), scalar(service, "local_host"),
                    static_cast<std::uint16_t>(number(service, "local_port", {.min = 1, .max = 65535}))};
                if (!security::valid_identifier(value.name) || !security::valid_hostname(value.hostname)) throw Error("invalid service name or hostname");
                loopback(value.local_host);
                if (!names.insert(value.name).second || !hostnames.insert(value.hostname).second) throw Error("duplicate service name or hostname");
                result.services.push_back(std::move(value));
            }
        }
        return result;
    } catch (const YAML::Exception&) {
        // yaml-cpp diagnostics may contain source text; do not expose secrets.
        throw Error("invalid YAML configuration");
    }
}
Gateway load_gateway(const std::filesystem::path& path) {
    try {
        const auto root = document(path);
        const auto mode = transport(root);
        if (mode == Transport::local_tcp) keys(root, {"transport", "gateway"});
        else keys(root, {"transport", "gateway", "security", "authorized_agents", "http"});
        const auto node = root["gateway"];
        if (mode == Transport::local_tcp) keys(node, {"bind_host", "port", "timeout_ms", "max_connections"});
        else keys(node, {"bind_host", "port", "timeout_ms", "max_connections", "heartbeat_interval_ms", "heartbeat_timeout_ms", "tunnel_buffer_budget_bytes", "write_timeout_ms"});
        Gateway result;
        result.bind_host = scalar(node, "bind_host");
        result.port = static_cast<std::uint16_t>(number(node, "port", {.min = 1, .max = 65535}));
        result.timeout = std::chrono::milliseconds(number(node, "timeout_ms", {.min = 100, .max = 60000}));
        result.max_connections = number(node, "max_connections", {.min = 1, .max = 1024});
        result.transport = mode;
        if (mode == Transport::local_tcp) loopback(result.bind_host);
        else {
            if (!ip_address(result.bind_host)) throw Error("gateway bind_host must be an IP literal");
            result.tls = tls_files(root["security"], path);
            if (node["tunnel_buffer_budget_bytes"]) result.tunnel_buffer_budget_bytes = number(node, "tunnel_buffer_budget_bytes", {.min = 16 * 1024 * 1024, .max = 1024 * 1024 * 1024});
            if (node["write_timeout_ms"]) result.write_timeout = std::chrono::milliseconds(number(node, "write_timeout_ms", {.min = 100, .max = 60000}));
            result.heartbeat_interval = std::chrono::milliseconds(number(node, "heartbeat_interval_ms", {.min = 100, .max = 60000}));
            result.heartbeat_timeout = std::chrono::milliseconds(number(node, "heartbeat_timeout_ms", {.min = 100, .max = 60000}));
            const auto agents = root["authorized_agents"];
            if (!agents.IsSequence() || agents.size() == 0 || agents.size() > 1024) throw Error("authorized_agents requires 1 to 1024 entries");
            std::set<std::string> names, fingerprints, hostnames;
            for (const auto& agent : agents) {
                keys(agent, {"name", "certificate_sha256", "services"});
                AuthorizedAgent value{scalar(agent, "name"), scalar(agent, "certificate_sha256"), {}};
                if (!security::valid_identifier(value.name) || !security::valid_fingerprint(value.certificate_sha256))
                    throw Error("invalid agent identity or fingerprint");
                if (!names.insert(value.name).second || !fingerprints.insert(value.certificate_sha256).second)
                    throw Error("duplicate authorized identity");
                if (const auto services = agent["services"]) {
                    if (!services.IsSequence() || services.size() > 32) throw Error("authorized services must contain at most 32 entries");
                    std::set<std::string> service_names;
                    for (const auto& service : services) {
                        keys(service, {"name", "hostname"});
                        PublishedService entry{scalar(service, "name"), scalar(service, "hostname")};
                        if (!security::valid_identifier(entry.name) || !security::valid_hostname(entry.hostname) ||
                            !service_names.insert(entry.name).second || !hostnames.insert(entry.hostname).second)
                            throw Error("invalid or duplicate authorized service");
                        value.services.push_back(std::move(entry));
                    }
                }
                result.authorized_agents.push_back(std::move(value));
            }
            if (const auto node_http = root["http"]) {
                keys(node_http, {"bind_host", "port", "security", "max_connections", "max_in_flight", "requests_per_second", "request_timeout_ms", "buffer_budget_bytes"});
                Https value;
                value.bind_host = scalar(node_http, "bind_host");
                if (!ip_address(value.bind_host)) throw Error("HTTPS bind_host must be an IP literal");
                value.port = static_cast<std::uint16_t>(number(node_http, "port", {.min = 1, .max = 65535}));
                if (value.port == result.port) throw Error("HTTPS and tunnel ports must differ");
                value.tls = tls_files(node_http["security"], path, false);
                value.max_connections = number(node_http, "max_connections", {.min = 1, .max = 256});
                value.max_in_flight = number(node_http, "max_in_flight", {.min = 1, .max = 64});
                value.requests_per_second = number(node_http, "requests_per_second", {.min = 1, .max = 10000});
                value.timeout = std::chrono::milliseconds(number(node_http, "request_timeout_ms", {.min = 100, .max = 60000}));
                if (node_http["buffer_budget_bytes"]) value.buffer_budget_bytes = number(node_http, "buffer_budget_bytes", {.min = 8 * 1024 * 1024, .max = 1024 * 1024 * 1024});
                if (hostnames.empty()) throw Error("HTTPS requires at least one authorized service");
                result.http = std::move(value);
            }
        }
        return result;
    } catch (const YAML::Exception&) {
        throw Error("invalid YAML configuration");
    }
}
} // namespace shadow::configuration
