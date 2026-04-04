#pragma once
#include <string>

namespace astharbor {
struct Fix {
    std::string fixId;
    std::string description;
    std::string safety; // safe, review, manual
    std::string replacementText;
    int offset = 0;
    int length = 0;
};
} // namespace astharbor
