#pragma once
#include "astharbor/finding.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <ostream>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
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
                    out << "  " << finding.line << ":" << finding.column << " [" << finding.ruleId
                        << "] " << finding.message << "\n";
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

            std::sort(applicableFixes.begin(), applicableFixes.end(),
                      [](const Fix *first, const Fix *second) {
                          if (first->offset == second->offset) {
                              return first->length < second->length;
                          }
                          return first->offset < second->offset;
                      });

            std::vector<const Fix *> validatedFixes;
            std::optional<size_t> previousEnd;
            for (const Fix *fix : applicableFixes) {
                if (fix->offset < 0 || fix->length < 0) {
                    result.errors.push_back("Invalid offset for fix: " + fix->fixId);
                    result.fixesSkipped++;
                    continue;
                }
                const auto start = static_cast<size_t>(fix->offset);
                const auto length = static_cast<size_t>(fix->length);
                if (previousEnd && *previousEnd > start) {
                    result.errors.push_back("Overlapping fix skipped: " + fix->fixId);
                    result.fixesSkipped++;
                    continue;
                }
                previousEnd = start + length;
                validatedFixes.push_back(fix);
            }

            if (validatedFixes.empty()) {
                continue;
            }

            std::ifstream inputStream(filePath, std::ios::binary);
            if (!inputStream) {
                result.errors.push_back("Cannot read: " + filePath);
                continue;
            }
            std::string content((std::istreambuf_iterator<char>(inputStream)),
                                std::istreambuf_iterator<char>());
            inputStream.close();

            if (backup) {
                std::ofstream backupStream(filePath + ".bak", std::ios::binary);
                if (!backupStream) {
                    result.errors.push_back("Cannot create backup: " + filePath + ".bak");
                    continue;
                }
                backupStream << content;
                backupStream.close();
                if (!backupStream) {
                    result.errors.push_back("Cannot write backup: " + filePath + ".bak");
                    continue;
                }
            }

            std::sort(
                validatedFixes.begin(), validatedFixes.end(),
                [](const Fix *first, const Fix *second) { return first->offset > second->offset; });

            for (const Fix *fix : validatedFixes) {
                const auto start = static_cast<size_t>(fix->offset);
                const auto length = static_cast<size_t>(fix->length);
                if (start <= content.size() && length <= content.size() - start) {
                    content.replace(start, length, fix->replacementText);
                    result.fixesApplied++;
                } else {
                    result.errors.push_back("Invalid offset for fix: " + fix->fixId);
                    result.fixesSkipped++;
                }
            }

            auto tempPath = temporaryPathFor(filePath);
            std::ofstream outputStream(tempPath, std::ios::binary | std::ios::trunc);
            if (!outputStream) {
                result.errors.push_back("Cannot write temporary file: " + tempPath.string());
                continue;
            }
            outputStream << content;
            outputStream.close();
            if (!outputStream) {
                result.errors.push_back("Cannot write temporary file: " + tempPath.string());
                std::error_code removeEc;
                std::filesystem::remove(tempPath, removeEc);
                continue;
            }

            std::error_code renameEc;
            std::filesystem::rename(tempPath, filePath, renameEc);
            if (renameEc) {
                result.errors.push_back("Cannot replace " + filePath + ": " + renameEc.message());
                std::error_code removeEc;
                std::filesystem::remove(tempPath, removeEc);
                continue;
            }
            result.filesModified++;
        }

        return result;
    }

  private:
    static std::filesystem::path temporaryPathFor(const std::string &filePath) {
        auto path = std::filesystem::path(filePath);
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        std::ostringstream suffix;
        suffix << ".astharbor.tmp." << now;
        return path.parent_path() / (path.filename().string() + suffix.str());
    }

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
