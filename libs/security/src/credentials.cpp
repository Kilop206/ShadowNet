#include <shadow/security/credentials.hpp>
#include <shadow/core/error.hpp>
#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <array>
#include <memory>
#include <vector>
#endif
namespace shadow::security {
void check_private_key(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status) || std::filesystem::hard_link_count(path, error) != 1 || error)
        throw Error("private key must be a regular file with one link");
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > 65536) throw Error("private key exceeds size bounds");
#ifdef _WIN32
    PSECURITY_DESCRIPTOR raw = nullptr;
    PSID owner = nullptr;
    PACL acl = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &acl, nullptr, &raw) != ERROR_SUCCESS) throw Error("cannot inspect private key ACL");
    const auto free_descriptor = [](void* value) { LocalFree(value); };
    const std::unique_ptr<void, decltype(free_descriptor)> descriptor(raw, free_descriptor);
    if (!acl || !IsValidAcl(acl)) throw Error("private key requires a restricted DACL");
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) throw Error("cannot inspect process identity");
    const auto close_token = [](void* value) { CloseHandle(value); };
    const std::unique_ptr<void, decltype(close_token)> token(raw_token, close_token);
    DWORD length = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &length);
    if (length == 0 || length > 65536) throw Error("invalid process identity");
    std::vector<unsigned char> information(length);
    if (!GetTokenInformation(token.get(), TokenUser, information.data(), length, &length)) throw Error("cannot inspect process identity");
    const auto* user = reinterpret_cast<const TOKEN_USER*>(information.data());
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> system{}, administrators{};
    DWORD system_size = static_cast<DWORD>(system.size()), admin_size = static_cast<DWORD>(administrators.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system.data(), &system_size) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators.data(), &admin_size)) throw Error("cannot inspect trusted identities");
    const auto trusted = [&](PSID sid) {
        return IsValidSid(sid) && (EqualSid(sid, user->User.Sid) || EqualSid(sid, system.data()) || EqualSid(sid, administrators.data()));
    };
    if (!trusted(owner)) throw Error("private key owner is not trusted");
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        void* ace = nullptr;
        if (!GetAce(acl, index, &ace)) throw Error("cannot inspect private key ACE");
        const auto* header = static_cast<const ACE_HEADER*>(ace);
        if ((header->AceFlags & INHERIT_ONLY_ACE) != 0 || header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) throw Error("unsupported private key ACE");
        const auto* grant = static_cast<const ACCESS_ALLOWED_ACE*>(ace);
        constexpr DWORD sensitive = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_READ | GENERIC_WRITE;
        if ((grant->Mask & sensitive) != 0 && !trusted(const_cast<DWORD*>(&grant->SidStart)))
            throw Error("private key ACL grants access to an untrusted identity");
    }
#else
    constexpr auto forbidden = std::filesystem::perms::group_all | std::filesystem::perms::others_all;
    if ((status.permissions() & forbidden) != std::filesystem::perms::none) throw Error("private key permissions must be 0600 or stricter");
#endif
}
} // namespace shadow::security
