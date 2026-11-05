#pragma once
#include <shadow/security/credentials.hpp>
#include <boost/asio/ssl/context.hpp>
#include <memory>
#include <string>

namespace shadow::security {
std::shared_ptr<boost::asio::ssl::context> make_tls_context(const TlsFiles& files, bool server);
std::shared_ptr<boost::asio::ssl::context> make_https_context(const TlsFiles& files);
void verify_server_identity(SSL* stream, const std::string& host);
std::string peer_fingerprint(SSL* stream);
std::string random_session_id();
} // namespace shadow::security
