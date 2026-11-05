#pragma once
#include <shadow/security/credentials.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace shadow::configuration {
enum class Transport : std::uint8_t { local_tcp, wss };
struct Reconnect {
    bool enabled = true;
    std::chrono::milliseconds initial{250};
    std::chrono::milliseconds maximum{30000};
};
struct PublishedService {
    std::string name;
    std::string hostname;
};
struct AuthorizedAgent {
    std::string name;
    std::string certificate_sha256;
    std::vector<PublishedService> services;
};
struct Service {
    std::string name;
    std::string hostname;
    std::string local_host;
    std::uint16_t local_port;
};
struct Agent {
    std::string name;
    std::string gateway_host;
    std::uint16_t port;
    std::chrono::milliseconds timeout;
    std::vector<Service> services;
    Transport transport = Transport::local_tcp;
    security::TlsFiles tls;
    Reconnect reconnect;
    std::size_t max_in_flight = 16;
    std::chrono::milliseconds backend_timeout{3000};
};
struct Https {
    std::string bind_host;
    std::uint16_t port = 8443;
    security::TlsFiles tls;
    std::size_t max_connections = 32;
    std::size_t max_in_flight = 16;
    unsigned requests_per_second = 100;
    std::chrono::milliseconds timeout{5000};
};
struct Gateway {
    std::string bind_host;
    std::uint16_t port;
    std::chrono::milliseconds timeout;
    std::size_t max_connections;
    Transport transport = Transport::local_tcp;
    security::TlsFiles tls;
    std::vector<AuthorizedAgent> authorized_agents;
    std::chrono::milliseconds heartbeat_interval{1000};
    std::chrono::milliseconds heartbeat_timeout{3000};
    std::optional<Https> http;
};
Agent load_agent(const std::filesystem::path& path);
Gateway load_gateway(const std::filesystem::path& path);
} // namespace shadow::configuration
