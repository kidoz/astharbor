#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityNoSystemCallRule : public Rule {
  public:
    std::string id() const override { return "security/no-system-call"; }
    std::string title() const override { return "No system()"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to system() which is vulnerable to command injection.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("system", "::system", "std::system"))))
                .bind("system_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("system_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "system() passes commands to the shell and is vulnerable to command injection "
            "(CWE-78) — use exec-family functions instead";
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
