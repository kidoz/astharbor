#pragma once
#include <string>
#include <vector>
#include "finding.hpp"
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Basic/SourceManager.h>

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
};
} // namespace astharbor
