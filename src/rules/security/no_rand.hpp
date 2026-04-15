#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityNoRandRule : public Rule {
  public:
    std::string id() const override { return "security/no-rand"; }
    std::string title() const override { return "No rand()"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to rand(), srand(), and random() which are cryptographically weak "
               "PRNGs.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("rand", "srand", "random", "::rand", "::srand",
                                                    "::random", "std::rand", "std::srand"))))
                .bind("rand_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("rand_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "rand()/srand()/random() are cryptographically weak (CWE-338) — use "
            "std::random_device, arc4random(), or getrandom() for security-sensitive contexts";
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
