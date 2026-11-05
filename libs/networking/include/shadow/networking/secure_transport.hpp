#pragma once
#include <shadow/configuration/config.hpp>

namespace shadow::networking {
int run_secure_gateway(const configuration::Gateway& config);
int run_secure_agent(const configuration::Agent& config);
} // namespace shadow::networking
