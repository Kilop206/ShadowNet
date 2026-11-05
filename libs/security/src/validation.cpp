#include <shadow/security/validation.hpp>

namespace shadow::security {
namespace {
bool alnum(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}
}
bool is_loopback(std::string_view value) noexcept {
    return value == "127.0.0.1" || value == "::1";
}
bool valid_fingerprint(std::string_view value) noexcept {
    if (value.size() != 64) return false;
    for (char c : value) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
bool valid_identifier(std::string_view value) noexcept {
    if (value.empty() || value.size() > 64) return false;
    for (char c : value) if (!alnum(c) && c != '-' && c != '_') return false;
    return true;
}
bool valid_hostname(std::string_view value) noexcept {
    if (value.empty() || value.size() > 253) return false;
    while (!value.empty()) {
        const auto dot = value.find('.');
        const auto label = value.substr(0, dot);
        if (label.empty() || label.size() > 63 || !alnum(label.front()) || !alnum(label.back())) return false;
        for (char c : label) if (!alnum(c) && c != '-') return false;
        if (dot == std::string_view::npos) return true;
        value.remove_prefix(dot + 1);
    }
    return false;
}
} // namespace shadow::security
