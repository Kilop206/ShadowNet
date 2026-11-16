#pragma once
#include <filesystem>

namespace shadow::security {
struct TlsFiles {
    std::filesystem::path ca_file;
    std::filesystem::path certificate_file;
    std::filesystem::path private_key_file;
    std::filesystem::path crl_file;
};
void check_private_key(const std::filesystem::path& path);
} // namespace shadow::security
