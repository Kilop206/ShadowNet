#include <catch2/catch_test_macros.hpp>
#include <shadow/configuration/config.hpp>
#include <shadow/core/error.hpp>
#include <shadow/observability/log.hpp>
#include <shadow/protocol/message.hpp>
#include <shadow/security/validation.hpp>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace {
struct File {
    std::filesystem::path directory;
    std::filesystem::path path;
    explicit File(const std::string& text) {
        static std::atomic<unsigned> next{0};
        directory = std::filesystem::temp_directory_path() / ("shadow-unit-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" + std::to_string(next++));
        std::filesystem::create_directory(directory);
        path = directory / "config.yaml";
        std::ofstream output(path, std::ios::binary);
        output << text;
        if (!output) throw std::runtime_error("test fixture write failed");
    }
    ~File() { std::error_code ignored; std::filesystem::remove_all(directory, ignored); }
};
const std::string agent = "transport: local_tcp\nagent:\n  name: home-server\n  gateway_host: 127.0.0.1\n  port: 7443\n  timeout_ms: 1000\n";
const std::string gateway = "transport: local_tcp\ngateway:\n  bind_host: 127.0.0.1\n  port: 7443\n  timeout_ms: 1000\n  max_connections: 8\n";
std::string replace(std::string text, const std::string& from, const std::string& to) {
    const auto index = text.find(from);
    REQUIRE(index != std::string::npos);
    text.replace(index, from.size(), to);
    return text;
}
}

TEST_CASE("protocol round trips every implemented message type") {
    for (auto type : {shadow::protocol::Type::hello, shadow::protocol::Type::hello_ack}) {
        const auto bytes = shadow::protocol::encode({type, "home-server"});
        REQUIRE(bytes.size() == 23);
        REQUIRE(bytes[11] == 11);
        auto header = shadow::protocol::decode_header(std::span(bytes).first(12));
        const auto message = shadow::protocol::decode_payload(header, std::span(bytes).subspan(12));
        CHECK(message.type == type);
        CHECK(message.name == "home-server");
    }
}
TEST_CASE("protocol rejects invalid fields before allocating payloads") {
    const auto valid = shadow::protocol::encode({shadow::protocol::Type::hello, "agent"});
    for (auto index : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
        auto bytes = valid;
        bytes[static_cast<std::size_t>(index)] = 255;
        CHECK_THROWS_AS(shadow::protocol::decode_header(std::span(bytes).first(12)), shadow::Error);
    }
    CHECK_THROWS_AS(shadow::protocol::decode_header(std::span(valid).first(11)), shadow::Error);
    auto bytes = valid;
    bytes[10] = 1; bytes[11] = 1; // 257 bytes.
    CHECK_THROWS_AS(shadow::protocol::decode_header(std::span(bytes).first(12)), shadow::Error);
    bytes[10] = 0; bytes[11] = 0;
    CHECK_THROWS_AS(shadow::protocol::decode_header(std::span(bytes).first(12)), shadow::Error);
    const auto header = shadow::protocol::decode_header(std::span(valid).first(12));
    CHECK_THROWS_AS(shadow::protocol::decode_payload(header, std::span(valid).subspan(13)), shadow::Error);
    for (const auto& name : {std::string{}, std::string(65, 'a'), std::string("bad\nname"), std::string("bad name")}) {
        CHECK_THROWS_AS(shadow::protocol::encode({shadow::protocol::Type::hello, name}), shadow::Error);
    }
    CHECK_NOTHROW(shadow::protocol::encode({shadow::protocol::Type::hello, std::string(64, 'a')}));
    bytes = valid; bytes[12] = 0;
    CHECK_THROWS_AS(shadow::protocol::decode_payload(header, std::span(bytes).subspan(12)), shadow::Error);
}
TEST_CASE("security validates canonical destinations and identifiers") {
    CHECK(shadow::security::is_loopback("127.0.0.1"));
    CHECK(shadow::security::is_loopback("::1"));
    for (auto host : {"localhost", "127.1", "0.0.0.0", "::", "10.0.0.1", "127.0.0.2", "2130706433"})
        CHECK_FALSE(shadow::security::is_loopback(host));
    for (auto host : {"api.example.test", "a", "a-b.example"}) CHECK(shadow::security::valid_hostname(host));
    for (auto host : {"", "a..b", "-a.com", "a-.com", "a.com.", "A.com", "a:80", "*.com", "a/b"})
        CHECK_FALSE(shadow::security::valid_hostname(host));
    CHECK_FALSE(shadow::security::valid_hostname(std::string(64, 'a') + ".com"));
}
TEST_CASE("shipped configurations load two distinct local services") {
    const auto root = std::filesystem::path(SHADOW_SOURCE_DIR);
    const auto config = shadow::configuration::load_agent(root / "config/agent.local.yaml");
    REQUIRE(config.services.size() == 2);
    CHECK(config.services[0].local_port == 8080);
    CHECK(config.services[1].hostname == "app.example.test");
    CHECK(shadow::configuration::load_gateway(root / "config/gateway.local.yaml").max_connections == 64);
}
TEST_CASE("agent configuration rejects unknown duplicate missing and unsafe fields") {
    for (const auto& text : {
        std::string{}, std::string("["), std::string("[]"), agent + "---\na: 1\n",
        agent + "security: {tls: false}\n", agent + "transport: local_tcp\n",
        replace(agent, "name: home-server", "name: bad name"),
        replace(agent, "gateway_host: 127.0.0.1", "gateway_host: localhost"),
        replace(agent, "gateway_host: 127.0.0.1", "gateway_host: 192.168.1.1"),
        replace(agent, "port: 7443", "port: 0"), replace(agent, "port: 7443", "port: 65536"),
        replace(agent, "port: 7443", "port: -1"), replace(agent, "port: 7443", "port: 0x10"),
        replace(agent, "port: 7443", "port: 9999999999999999999999"),
        replace(agent, "port: 7443", "port: [7443]"), replace(agent, "port: 7443", "other: 7443"),
        replace(agent, "timeout_ms: 1000", "timeout_ms: 99"),
        replace(agent, "timeout_ms: 1000", "timeout_ms: 60001"),
        agent + "services: {}\n", std::string(65537, ' ')}) {
        CAPTURE(text.substr(0, 250));
        const File file(text);
        CHECK_THROWS_AS(shadow::configuration::load_agent(file.path), shadow::Error);
    }
    const File good(replace(agent, "127.0.0.1", "::1"));
    CHECK(shadow::configuration::load_agent(good.path).gateway_host == "::1");
    CHECK_THROWS_AS(shadow::configuration::load_agent(good.directory / "absent"), shadow::Error);
}
TEST_CASE("service allowlist rejects duplicates and nonlocal endpoints") {
    const std::string service = "  - {name: api, hostname: api.example.test, local_host: 127.0.0.1, local_port: 8080}\n";
    for (const auto& services : {
        service + service, service + replace(service, "name: api", "name: other"),
        service + replace(service, "hostname: api.example.test", "hostname: other.example.test"),
        replace(service, "127.0.0.1", "169.254.169.254"),
        replace(service, "api.example.test", "bad/host"), replace(service, "8080", "65536")}) {
        const File file(agent + "services:\n" + services);
        CHECK_THROWS_AS(shadow::configuration::load_agent(file.path), shadow::Error);
    }
    std::string many;
    for (unsigned i = 0; i < 33; ++i) many += "  - {name: a" + std::to_string(i) + ", hostname: a" +
        std::to_string(i) + ".test, local_host: 127.0.0.1, local_port: 80}\n";
    const File file(agent + "services:\n" + many);
    CHECK_THROWS_AS(shadow::configuration::load_agent(file.path), shadow::Error);
}
TEST_CASE("gateway rejects public binds connection floods and invalid timeouts") {
    for (const auto& text : {
        replace(gateway, "127.0.0.1", "0.0.0.0"), replace(gateway, "127.0.0.1", "::"),
        replace(gateway, "connections: 8", "connections: 0"), replace(gateway, "connections: 8", "connections: 1025"),
        replace(gateway, "local_tcp", "wss"), replace(gateway, "port: 7443", "port: 65536"),
        replace(gateway, "timeout_ms: 1000", "timeout_ms: 1"),
        gateway + "services: []\n", replace(gateway, "  port: 7443", "  port: 7443\n  port: 7444")}) {
        const File file(text);
        CHECK_THROWS_AS(shadow::configuration::load_gateway(file.path), shadow::Error);
    }
}
TEST_CASE("logs cannot inject extra lines or emit terminal control sequences") {
    std::ostringstream output;
    shadow::observability::write_log(output, shadow::observability::Level::warning, "agent\nforged", "event\r\n\x1b[31m");
    const auto line = output.str();
    CHECK(line.find("level=WARN") != std::string::npos);
    CHECK(line.find("agent?forged") != std::string::npos);
    CHECK(line.find('\r') == std::string::npos);
    CHECK(line.find('\x1b') == std::string::npos);
    CHECK(line.find('\n') == line.size() - 1);
    output.str("");
    shadow::observability::write_log(output, shadow::observability::Level::info, "agent", std::string(10000, 'x'));
    CHECK(output.str().size() < 650);
}
