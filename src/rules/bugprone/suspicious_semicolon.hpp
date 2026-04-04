#pragma once

#include "astharbor/rule.hpp"

namespace astharbor {
class BugproneSuspiciousSemicolonRule : public Rule {
  public:
    std::string id() const override { return "bugprone/suspicious-semicolon"; }
    std::string title() const override { return "Suspicious semicolon"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Detects if-statements whose body is only a stray semicolon.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(ifStmt(hasThen(nullStmt().bind("null_body"))), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        if (const auto *Body = Result.Nodes.getNodeAs<clang::NullStmt>("null_body")) {
            auto &sourceManager = *Result.SourceManager;

            Finding finding;
            finding.ruleId = id();
            finding.message = "If statement has an empty body; this is often caused by a stray semicolon";
            finding.severity = defaultSeverity();
            finding.category = category();
            finding.file = sourceManager.getFilename(Body->getSemiLoc()).str();
            finding.line = sourceManager.getSpellingLineNumber(Body->getSemiLoc());
            finding.column = sourceManager.getSpellingColumnNumber(Body->getSemiLoc());

            if (!finding.file.empty()) {
                findings.push_back(finding);
            }
        }
    }
};
} // namespace astharbor
