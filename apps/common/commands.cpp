#include "commands.hpp"
#include <shadow/core/error.hpp>
#include <shadow/configuration/config.hpp>
#include <shadow/networking/local_transport.hpp>
#include <shadow/observability/log.hpp>
#include <iostream>
#include <string>
#include <vector>

namespace shadow::commands {
namespace {
int usage(std::string_view executable, bool valid) {
    if (executable == "shadow") {
        std::cout << "ShadowNet " << version << " (milestone 1, local diagnostic only)\n"
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
            if (args[3] == "agent") (void)configuration::load_agent(args[5]);
            else if (args[3] == "gateway") (void)configuration::load_gateway(args[5]);
            else return usage(executable, false);
            std::cout << "Configuration valid (milestone 1 local_tcp schema)\n";
            return 0;
        }
        std::string component(executable);
        if (executable == "shadow") {
            if (args.size() != 4 || args[1] != "start" || (args[0] != "agent" && args[0] != "gateway")) return usage(executable, false);
            component = "shadow-" + args[0];
            args.erase(args.begin(), args.begin() + 2);
        }
        if (args.size() != 2 || args[0] != "--config") return usage(executable, false);
        if (component == "shadow-agent") return networking::run_agent(configuration::load_agent(args[1]));
        return networking::run_gateway(configuration::load_gateway(args[1]));
    } catch (const Error& error) {
        observability::log(observability::Level::error, executable, error.what());
        return 1;
    } catch (const std::exception&) {
        observability::log(observability::Level::error, executable, "startup_or_runtime_failure");
        return 1;
    }
}
} // namespace shadow::commands
