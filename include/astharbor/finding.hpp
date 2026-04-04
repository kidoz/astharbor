#pragma once
#include <string>
#include <vector>
#include "fix.hpp"

namespace astharbor {
struct Finding {
    std::string findingId;
    std::string ruleId;
    std::string severity;
    std::string message;
    std::string category;
    std::string file;
    int line = 0;
    int column = 0;
    std::vector<Fix> fixes;
};
} // namespace astharbor
