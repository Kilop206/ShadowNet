#include <shadow/configuration/config.hpp>
#include <shadow/core/error.hpp>
#include <shadow/security/validation.hpp>
#include <yaml-cpp/yaml.h>
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
    if (result.empty() || result.size() > 1024) throw Error(std::string("invalid field length: ") + key);
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
void transport(const YAML::Node& root) {
    if (scalar(root, "transport") != "local_tcp") throw Error("only local_tcp is implemented in milestone 1");
}
void loopback(const std::string& host) {
    if (!security::is_loopback(host)) throw Error("milestone 1 requires literal 127.0.0.1 or ::1");
}
}
Agent load_agent(const std::filesystem::path& path) {
    try {
        const auto root = document(path);
        keys(root, {"transport", "agent", "services"});
        transport(root);
        const auto node = root["agent"];
        keys(node, {"name", "gateway_host", "port", "timeout_ms"});
        Agent result{scalar(node, "name"), scalar(node, "gateway_host"),
            static_cast<std::uint16_t>(number(node, "port", {.min = 1, .max = 65535})),
            std::chrono::milliseconds(number(node, "timeout_ms", {.min = 100, .max = 60000})), {}};
        if (!security::valid_identifier(result.name)) throw Error("invalid agent name");
        loopback(result.gateway_host);
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
        keys(root, {"transport", "gateway"});
        transport(root);
        const auto node = root["gateway"];
        keys(node, {"bind_host", "port", "timeout_ms", "max_connections"});
        Gateway result{scalar(node, "bind_host"), static_cast<std::uint16_t>(number(node, "port", {.min = 1, .max = 65535})),
            std::chrono::milliseconds(number(node, "timeout_ms", {.min = 100, .max = 60000})),
            number(node, "max_connections", {.min = 1, .max = 1024})};
        loopback(result.bind_host);
        return result;
    } catch (const YAML::Exception&) {
        throw Error("invalid YAML configuration");
    }
}
} // namespace shadow::configuration
