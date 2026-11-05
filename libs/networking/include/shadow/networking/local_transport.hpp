#pragma once
#include <shadow/configuration/config.hpp>

namespace shadow::networking {
// Foreground diagnostic programs. No forwarding, authentication or TLS in M1.
// All handlers and connection state run on one io_context thread.
int run_gateway(const configuration::Gateway& config);
int run_agent(const configuration::Agent& config);
} // namespace shadow::networking
