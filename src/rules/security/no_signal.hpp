#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityNoSignalRule : public Rule {
  public:
    std::string id() const override { return "security/no-signal"; }
    std::string title() const override { return "No signal()"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to signal() which has race-condition and portability issues — use sigaction() instead.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("signal", "::signal"))))
                .bind("signal_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("signal_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "signal() has undefined behavior with concurrent signals and portability issues "
            "(CWE-364) — use sigaction() instead";
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
