#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityNoAllocaRule : public Rule {
  public:
    std::string id() const override { return "security/no-alloca"; }
    std::string title() const override { return "No alloca()"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to alloca() which allocates on the stack with no overflow "
               "protection.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(callExpr(callee(functionDecl(hasAnyName("alloca", "__builtin_alloca",
                                                                  "_alloca", "::alloca"))))
                              .bind("alloca_call"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("alloca_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "alloca() allocates on the stack without overflow protection — use heap allocation or "
            "fixed-size buffers instead";
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
