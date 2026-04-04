#pragma once
#include "astharbor/finding.hpp"
#include <algorithm>
#include <fstream>
#include <map>
#include <ostream>
#include <string>
#include <vector>

namespace astharbor {

class FixApplicator {
  public:
    struct ApplyResult {
        int filesModified = 0;
        int fixesApplied = 0;
        int fixesSkipped = 0;
        std::vector<std::string> errors;
    };

    static void preview(const std::vector<Finding> &findings, std::ostream &out) {
        auto grouped = groupByFile(findings);
        for (const auto &[filePath, fileFindings] : grouped) {
            out << "--- " << filePath << " ---\n";
            for (const auto &finding : fileFindings) {
                for (const auto &fix : finding.fixes) {
                    out << "  " << finding.line << ":" << finding.column << " ["
                        << finding.ruleId << "] " << finding.message << "\n";
                    out << "  Fix (" << fix.safety << "): " << fix.description << "\n";
                    out << "    Replace " << fix.length << " bytes at offset " << fix.offset
                        << " with \"" << fix.replacementText << "\"\n\n";
                }
            }
        }
        int totalFixes = 0;
        int safeFixes = 0;
        for (const auto &finding : findings) {
            for (const auto &fix : finding.fixes) {
                totalFixes++;
                if (fix.safety == "safe") {
                    safeFixes++;
                }
            }
        }
        out << "Summary: " << totalFixes << " fix(es) available (" << safeFixes << " safe)\n";
    }

    static ApplyResult apply(const std::vector<Finding> &findings, bool backup,
                             bool safeOnly = true) {
        ApplyResult result;
        auto grouped = groupByFile(findings);

        for (auto &[filePath, fileFindings] : grouped) {
            std::vector<const Fix *> applicableFixes;
            for (const auto &finding : fileFindings) {
                for (const auto &fix : finding.fixes) {
                    if (!safeOnly || fix.safety == "safe") {
                        applicableFixes.push_back(&fix);
                    } else {
                        result.fixesSkipped++;
                    }
                }
            }

            if (applicableFixes.empty()) {
                continue;
            }

            // Sort by offset descending so applying from end preserves earlier offsets
            std::sort(applicableFixes.begin(), applicableFixes.end(),
                      [](const Fix *first, const Fix *second) {
                          return first->offset > second->offset;
                      });

            std::ifstream inputStream(filePath);
            if (!inputStream) {
                result.errors.push_back("Cannot read: " + filePath);
                continue;
            }
            std::string content((std::istreambuf_iterator<char>(inputStream)),
                                std::istreambuf_iterator<char>());
            inputStream.close();

            if (backup) {
                std::ofstream backupStream(filePath + ".bak");
                if (!backupStream) {
                    result.errors.push_back("Cannot create backup: " + filePath + ".bak");
                    continue;
                }
                backupStream << content;
            }

            for (const Fix *fix : applicableFixes) {
                if (fix->offset >= 0 &&
                    static_cast<size_t>(fix->offset + fix->length) <= content.size()) {
                    content.replace(fix->offset, fix->length, fix->replacementText);
                    result.fixesApplied++;
                } else {
                    result.errors.push_back("Invalid offset for fix: " + fix->fixId);
                    result.fixesSkipped++;
                }
            }

            std::ofstream outputStream(filePath);
            if (!outputStream) {
                result.errors.push_back("Cannot write: " + filePath);
                continue;
            }
            outputStream << content;
            result.filesModified++;
        }

        return result;
    }

  private:
    static std::map<std::string, std::vector<Finding>>
    groupByFile(const std::vector<Finding> &findings) {
        std::map<std::string, std::vector<Finding>> grouped;
        for (const auto &finding : findings) {
            if (!finding.fixes.empty()) {
                grouped[finding.file].push_back(finding);
            }
        }
        return grouped;
    }
};

} // namespace astharbor
