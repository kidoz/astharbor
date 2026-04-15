#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityNoAtoiRule : public Rule {
  public:
    std::string id() const override { return "security/no-atoi-atol-atof"; }
    std::string title() const override { return "No atoi/atol/atof"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to atoi(), atol(), atoll(), and atof() which cannot distinguish "
               "parse errors from valid zero input.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("atoi", "atol", "atoll", "atof", "::atoi",
                                                    "::atol", "::atoll", "::atof", "std::atoi",
                                                    "std::atol", "std::atoll", "std::atof"))))
                .bind("atoi_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("atoi_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        const auto *Callee = Call->getDirectCallee();
        if (Callee == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        const std::string FunctionName = Callee->getName().str();

        Finding finding;
        finding.ruleId = id();
        finding.message = FunctionName + "() cannot distinguish parse errors from valid zero — use "
                                         "strtol/strtoul/strtod with errno checking instead";
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
