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
    /// File path -> hex content hash for every file whose content must be
    /// tracked across runs. Includes both the TU sources analyzed in this
    /// run AND the user-header files they transitively included — the
    /// header set is needed so `--incremental` can invalidate a TU when
    /// one of its dependencies changes even if the TU itself did not.
    std::map<std::string, std::string> fileHashes;
    /// Source path -> list of absolute user-header paths the TU included
    /// during analysis. Populated when the dependency collector is wired
    /// up; an empty entry just means "no known deps" and falls back to
    /// same-file-only invalidation.
    std::map<std::string, std::vector<std::string>> dependencies;
};
} // namespace astharbor
