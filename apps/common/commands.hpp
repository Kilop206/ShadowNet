#pragma once
#include <string_view>
namespace shadow::commands {
int execute(int argc, char** argv, std::string_view executable);
}
