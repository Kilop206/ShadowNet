#include "commands.hpp"
#include <shadow/core/error.hpp>
#include <shadow/configuration/config.hpp>
#include <shadow/networking/local_transport.hpp>
#include <shadow/networking/secure_transport.hpp>
#include <shadow/security/tls.hpp>
#include <shadow/observability/log.hpp>
#include <iostream>
#include <string>
#include <vector>

namespace shadow::commands {
namespace {
int usage(std::string_view executable, bool valid) {
    if (executable == "shadow") {
        std::cout << "ShadowNet " << version << " (WSS/mTLS tunnel and local diagnostic)\n"
                  << "shadow version\nshadow agent start --config FILE\nshadow gateway start --config FILE\n"
                  << "shadow config validate --type agent|gateway --config FILE\n";
    } else {
        std::cout << executable << " --config FILE\n" << executable << " --version\n";
    }
    return valid ? 0 : 2;
}
}
int execute(int argc, char** argv, std::string_view executable) {
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        if (args.size() == 1 && args[0] == "--help") return usage(executable, true);
        if (args.size() == 1 && (args[0] == "--version" || (executable == "shadow" && args[0] == "version"))) {
            std::cout << "ShadowNet " << version << '\n';
            return 0;
        }
        if (executable == "shadow" && args.size() == 6 && args[0] == "config" && args[1] == "validate" &&
            args[2] == "--type" && args[4] == "--config") {
            if (args[3] == "agent") {
                const auto config = configuration::load_agent(args[5]);
                if (config.transport == configuration::Transport::wss) (void)security::make_tls_context(config.tls, false);
            } else if (args[3] == "gateway") {
                const auto config = configuration::load_gateway(args[5]);
                if (config.transport == configuration::Transport::wss) (void)security::make_tls_context(config.tls, true);
            }
            else return usage(executable, false);
            std::cout << "Configuration valid\n";
            return 0;
        }
        std::string component(executable);
        if (executable == "shadow") {
            if (args.size() != 4 || args[1] != "start" || (args[0] != "agent" && args[0] != "gateway")) return usage(executable, false);
            component = "shadow-" + args[0];
            args.erase(args.begin(), args.begin() + 2);
        }
        if (args.size() != 2 || args[0] != "--config") return usage(executable, false);
        if (component == "shadow-agent") {
            const auto config = configuration::load_agent(args[1]);
            return config.transport == configuration::Transport::wss ? networking::run_secure_agent(config) : networking::run_agent(config);
        }
        const auto config = configuration::load_gateway(args[1]);
        return config.transport == configuration::Transport::wss ? networking::run_secure_gateway(config) : networking::run_gateway(config);
    } catch (const Error& error) {
        observability::log(observability::Level::error, executable, error.what());
        return 1;
    } catch (const std::exception&) {
        observability::log(observability::Level::error, executable, "startup_or_runtime_failure");
        return 1;
    }
}
} // namespace shadow::commands
