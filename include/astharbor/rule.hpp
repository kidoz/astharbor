#pragma once
#include "finding.hpp"
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Basic/SourceManager.h>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace astharbor {
class Rule : public clang::ast_matchers::MatchFinder::MatchCallback {
  public:
    ~Rule() override = default;
    virtual std::string id() const = 0;
    virtual std::string title() const = 0;
    virtual std::string category() const = 0;
    virtual std::string summary() const = 0;
    virtual std::string defaultSeverity() const = 0;
    virtual void registerMatchers(clang::ast_matchers::MatchFinder &Finder) = 0;

    std::vector<Finding> getFindings() const { return findings; }

  protected:
    std::vector<Finding> findings;

    static bool isInSystemHeader(clang::SourceLocation location,
                                 const clang::SourceManager &sourceManager) {
        if (location.isInvalid()) {
            return true;
        }
        auto expansionLoc = sourceManager.getExpansionLoc(location);
        return sourceManager.isInSystemHeader(expansionLoc);
    }

    /// Build a `Finding` pre-populated with this rule's metadata and the
    /// source location decomposed from `location`. Returns nullopt if the
    /// location is in a system header or its filename cannot be resolved —
    /// callers can safely early-return without emitting anything.
    std::optional<Finding> makeFinding(clang::SourceLocation location,
                                       const clang::SourceManager &sourceManager,
                                       std::string message) const {
        if (isInSystemHeader(location, sourceManager)) {
            return std::nullopt;
        }
        auto expansion = sourceManager.getExpansionLoc(location);
        std::string file = sourceManager.getFilename(expansion).str();
        if (file.empty()) {
            return std::nullopt;
        }
        // A single `getDecomposedLoc` call gives us both line and column
        // without recomputing the decomposition twice.
        auto decomposed = sourceManager.getDecomposedLoc(expansion);
        bool invalid = false;
        unsigned line =
            sourceManager.getLineNumber(decomposed.first, decomposed.second, &invalid);
        unsigned column =
            sourceManager.getColumnNumber(decomposed.first, decomposed.second, &invalid);

        Finding finding;
        finding.ruleId = id();
        finding.category = category();
        finding.severity = defaultSeverity();
        finding.message = std::move(message);
        finding.file = std::move(file);
        finding.line = static_cast<int>(line);
        finding.column = static_cast<int>(column);
        return finding;
    }

    /// Convenience: emit a Finding with no attached fixes.
    void emitFinding(clang::SourceLocation location,
                     const clang::SourceManager &sourceManager, std::string message) {
        if (auto finding = makeFinding(location, sourceManager, std::move(message))) {
            findings.push_back(std::move(*finding));
        }
    }

    /// Generate a stable fixId scoped to this rule — suffixed by the current
    /// finding count so ids are monotonic within a single run.
    std::string nextFixId(std::string_view prefix) const {
        return std::string(prefix) + "-" + std::to_string(findings.size());
    }
};
} // namespace astharbor
