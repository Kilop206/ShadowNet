#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace shadow::configuration {
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
};
struct Gateway {
    std::string bind_host;
    std::uint16_t port;
    std::chrono::milliseconds timeout;
    std::size_t max_connections;
};
Agent load_agent(const std::filesystem::path& path);
Gateway load_gateway(const std::filesystem::path& path);
} // namespace shadow::configuration
