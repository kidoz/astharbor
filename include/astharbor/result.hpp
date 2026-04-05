#pragma once
#include "finding.hpp"
#include <map>
#include <string>
#include <vector>

namespace astharbor {
struct AnalysisResult {
    std::string runId;
    bool success = true;
    std::vector<Finding> findings;
    /// File path -> hex content hash for every TU analyzed in this run.
    /// Populated when the analyzer knows the source list; consumed by
    /// `--incremental` on the next run to skip unchanged files.
    std::map<std::string, std::string> fileHashes;
};
} // namespace astharbor
