#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityNoGetsRule : public Rule {
  public:
    std::string id() const override { return "security/no-gets"; }
    std::string title() const override { return "No gets()"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to gets(), which has no bounds checking and was removed from C11.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("gets", "::gets")))).bind("gets_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("gets_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message = "Call to gets() is inherently unsafe with no bounds checking — use fgets() or getline() instead";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(Call->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(Call->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(Call->getExprLoc());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};
} // namespace astharbor
