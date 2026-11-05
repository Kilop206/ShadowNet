#include <shadow/security/tls.hpp>
#include <shadow/core/error.hpp>
#include <boost/asio/ip/address.hpp>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <array>
#include <span>
#include <cstdint>

namespace shadow::security {
namespace {
std::string hex(std::span<const unsigned char> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (auto byte : bytes) { result += digits[byte >> 4U]; result += digits[byte & 15U]; }
    return result;
}
void require(bool success) { if (!success) throw Error("TLS configuration failed"); }
enum class Role : std::uint8_t { agent, gateway, https };
std::shared_ptr<boost::asio::ssl::context> make_context(const TlsFiles& files, Role role) {
    try {
        namespace ssl = boost::asio::ssl;
        const bool server = role != Role::agent;
        auto context = std::make_shared<ssl::context>(server ? ssl::context::tls_server : ssl::context::tls_client);
        auto* handle = context->native_handle();
        require(SSL_CTX_set_min_proto_version(handle, TLS1_3_VERSION) == 1);
        require(SSL_CTX_set_max_proto_version(handle, TLS1_3_VERSION) == 1);
        require(SSL_CTX_set_max_early_data(handle, 0) == 1);
        SSL_CTX_set_session_cache_mode(handle, SSL_SESS_CACHE_OFF);
        if (server) require(SSL_CTX_set_num_tickets(handle, 0) == 1);
        SSL_CTX_set_max_cert_list(handle, 32768);
        SSL_CTX_set_verify_depth(handle, 4);
        require(X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(handle), X509_V_FLAG_X509_STRICT) == 1);
        context->set_password_callback([](std::size_t, ssl::context::password_purpose) { return std::string{}; });
        if (role != Role::https) context->load_verify_file(files.ca_file.string());
        context->use_certificate_chain_file(files.certificate_file.string());
        context->use_private_key_file(files.private_key_file.string(), ssl::context::pem);
        require(SSL_CTX_check_private_key(handle) == 1);
        auto* certificate = SSL_CTX_get0_certificate(handle);
        require(certificate != nullptr && X509_cmp_current_time(X509_get0_notBefore(certificate)) < 0 &&
            X509_cmp_current_time(X509_get0_notAfter(certificate)) > 0);
        require(X509_check_purpose(certificate, server ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT, 0) == 1);
        // OpenSSL/Asio define these positive verification bit flags as signed int.
        if (role == Role::https) context->set_verify_mode(ssl::verify_none);
        else context->set_verify_mode(server ? ssl::verify_peer | ssl::verify_fail_if_no_peer_cert : ssl::verify_peer); // NOLINT(bugprone-signed-bitwise)
        return context;
    } catch (const std::exception&) {
        // OpenSSL/Asio error text may contain paths or other sensitive context.
        throw Error("TLS credentials or context are invalid");
    }
}
} // namespace
std::shared_ptr<boost::asio::ssl::context> make_tls_context(const TlsFiles& files, bool server) {
    return make_context(files, server ? Role::gateway : Role::agent);
}
std::shared_ptr<boost::asio::ssl::context> make_https_context(const TlsFiles& files) {
    return make_context(files, Role::https);
}
void verify_server_identity(SSL* stream, const std::string& host) {
    boost::system::error_code error;
    (void)boost::asio::ip::make_address(host, error);
    auto* parameters = SSL_get0_param(stream);
    X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!error) require(X509_VERIFY_PARAM_set1_ip_asc(parameters, host.c_str()) == 1);
    else {
        require(SSL_set_tlsext_host_name(stream, host.c_str()) == 1);
        require(SSL_set1_host(stream, host.c_str()) == 1);
    }
}
std::string peer_fingerprint(SSL* stream) {
    std::unique_ptr<X509, decltype(&X509_free)> certificate(SSL_get1_peer_certificate(stream), X509_free);
    if (!certificate || SSL_get_verify_result(stream) != X509_V_OK) throw Error("peer certificate is not verified");
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    require(X509_digest(certificate.get(), EVP_sha256(), digest.data(), &length) == 1 && length == 32);
    return hex(std::span(digest).first(length));
}
std::string random_session_id() {
    std::array<unsigned char, 16> bytes{};
    require(RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) == 1);
    return hex(bytes);
}
} // namespace shadow::security
