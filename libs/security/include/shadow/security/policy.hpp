#pragma once
#include <string>
#include <string_view>
#include <vector>
namespace shadow::security {
struct HttpPolicy {
    std::vector<std::string> methods{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};
    std::vector<std::string> path_prefixes{"/"};
};
std::string canonical_path(std::string_view target);
bool allowed(const HttpPolicy& policy, std::string_view method, std::string_view target);
void validate_policy(const HttpPolicy& policy);
} // namespace shadow::security
