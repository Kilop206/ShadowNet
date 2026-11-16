#include <shadow/security/policy.hpp>
#include <shadow/core/error.hpp>
#include <algorithm>
#include <set>
namespace shadow::security {
namespace {
int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
bool unreserved(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        std::string_view("-._~").find(c) != std::string_view::npos;
}
void require(bool value) { if (!value) throw Error("ambiguous HTTP path or invalid access policy"); }
}
std::string canonical_path(std::string_view target) {
    require(!target.empty() && target.size() <= 8192);
    if (target == "*") return "*";
    require(target.front() == '/');
    const auto path = target.substr(0, target.find('?'));
    std::string result;
    for (std::size_t i = 0; i < path.size(); ++i) {
        char c = path[i];
        if (c == '%') {
            require(i + 2 < path.size() && hex(path[i + 1]) >= 0 && hex(path[i + 2]) >= 0);
            c = static_cast<char>(hex(path[i + 1]) * 16 + hex(path[i + 2])); i += 2;
            require(unreserved(c)); // No encoded slash, backslash, %, controls or reserved delimiters.
        }
        require(c > 32 && static_cast<unsigned char>(c) < 127 && c != '\\' && c != '#' && c != ';');
        result += c;
    }
    require(result.find("//") == std::string::npos);
    std::size_t start = 1;
    while (start < result.size()) {
        const auto end = result.find('/', start);
        const auto segment = std::string_view(result).substr(start, end == std::string::npos ? end : end - start);
        require(segment != "." && segment != "..");
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}
// Named HTTP fields follow the method/target convention used by the protocol.
bool allowed(const HttpPolicy& policy, std::string_view method, std::string_view target) { // NOLINT(bugprone-easily-swappable-parameters)
    if (std::find(policy.methods.begin(), policy.methods.end(), method) == policy.methods.end()) return false;
    const auto path = canonical_path(target);
    for (const auto& prefix : policy.path_prefixes) {
        if (prefix == "/") return true;
        if (path == prefix || (path.starts_with(prefix) && path.size() > prefix.size() && path[prefix.size()] == '/')) return true;
    }
    return false;
}
void validate_policy(const HttpPolicy& policy) {
    require(!policy.methods.empty() && policy.methods.size() <= 16 && !policy.path_prefixes.empty() && policy.path_prefixes.size() <= 16);
    std::set<std::string> methods, prefixes;
    for (const auto& method : policy.methods) {
        require(!method.empty() && method.size() <= 32 && method != "CONNECT" && method != "TRACE");
        for (char c : method) require(c >= 'A' && c <= 'Z');
        require(methods.insert(method).second);
    }
    for (const auto& prefix : policy.path_prefixes) {
        require(prefix.size() <= 2048 && prefix != "*" && prefix.find('?') == std::string::npos && canonical_path(prefix) == prefix);
        require(prefix == "/" || prefix.back() != '/');
        require(prefixes.insert(prefix).second);
    }
}
} // namespace shadow::security
