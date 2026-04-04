#pragma once
#include <string>
#include <vector>
#include "finding.hpp"

namespace astharbor {
struct AnalysisResult {
    std::string runId;
    bool success = true;
    std::vector<Finding> findings;
};
} // namespace astharbor
