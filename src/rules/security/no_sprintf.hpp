#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityNoSprintfRule : public Rule {
  public:
    std::string id() const override { return "security/no-sprintf"; }
    std::string title() const override { return "No sprintf()"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to sprintf() which performs unbounded writes and can cause buffer "
               "overflows.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(callExpr(callee(functionDecl(hasAnyName("sprintf", "wsprintf",
                                                                  "::sprintf", "std::sprintf"))))
                              .bind("sprintf_call"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("sprintf_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message = "sprintf() performs unbounded writes — use snprintf() instead";
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
