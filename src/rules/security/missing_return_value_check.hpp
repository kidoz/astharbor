#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/ParentMapContext.h>

namespace astharbor {
class SecurityMissingReturnValueCheckRule : public Rule {
  public:
    std::string id() const override { return "security/missing-return-value-check"; }
    std::string title() const override { return "Missing return value check"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to privilege-dropping functions (setuid, setgid, etc.) whose return "
               "value is discarded.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName(
                         "setuid", "setgid", "seteuid", "setegid",
                         "setresuid", "setresgid",
                         "::setuid", "::setgid", "::seteuid", "::setegid"))))
                .bind("privilege_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("privilege_call");
        if (Call == nullptr || Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }

        if (isReturnValueUsed(*Call, *Result.Context)) {
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
        finding.message = FunctionName +
                          "() return value is not checked — failure to drop privileges silently is a security "
                          "vulnerability (CWE-273)";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(Call->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(Call->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(Call->getExprLoc());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }

  private:
    static bool isReturnValueUsed(const clang::CallExpr &Call, clang::ASTContext &Context) {
        auto Parents = Context.getParents(Call);
        if (Parents.empty()) {
            return false;
        }

        // If the direct parent is a CompoundStmt, the value is discarded
        if (Parents[0].get<clang::CompoundStmt>()) {
            return false;
        }

        return true;
    }
};
} // namespace astharbor
