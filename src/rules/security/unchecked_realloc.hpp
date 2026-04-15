#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityUncheckedReallocRule : public Rule {
  public:
    std::string id() const override { return "security/unchecked-realloc"; }
    std::string title() const override { return "Unchecked realloc"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects p = realloc(p, n) where realloc failure loses the original pointer and "
               "leaks memory.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            binaryOperator(
                isAssignmentOperator(),
                hasLHS(ignoringParenImpCasts(declRefExpr().bind("lhs_ref"))),
                hasRHS(ignoringParenImpCasts(callExpr(
                    callee(functionDecl(hasAnyName("realloc", "::realloc", "std::realloc"))),
                    hasArgument(0, ignoringParenImpCasts(declRefExpr().bind("rhs_ref")))))))
                .bind("realloc_assign"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *LeftRef = Result.Nodes.getNodeAs<clang::DeclRefExpr>("lhs_ref");
        const auto *RightRef = Result.Nodes.getNodeAs<clang::DeclRefExpr>("rhs_ref");
        const auto *AssignOp = Result.Nodes.getNodeAs<clang::BinaryOperator>("realloc_assign");

        if (LeftRef == nullptr || RightRef == nullptr || AssignOp == nullptr ||
            Result.SourceManager == nullptr) {
            return;
        }

        if (LeftRef->getDecl() != RightRef->getDecl()) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "realloc() result assigned directly to the same pointer — if realloc fails, "
            "the original allocation is leaked. Use a temporary pointer instead";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(AssignOp->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(AssignOp->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(AssignOp->getExprLoc());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};
} // namespace astharbor
