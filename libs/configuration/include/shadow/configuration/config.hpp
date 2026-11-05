#pragma once
#include <shadow/security/credentials.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace shadow::configuration {
enum class Transport : std::uint8_t { local_tcp, wss };
struct Reconnect {
    bool enabled = true;
    std::chrono::milliseconds initial{250};
    std::chrono::milliseconds maximum{30000};
};
struct AuthorizedAgent {
    std::string name;
    std::string certificate_sha256;
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
};
Agent load_agent(const std::filesystem::path& path);
Gateway load_gateway(const std::filesystem::path& path);
} // namespace shadow::configuration
