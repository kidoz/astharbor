#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class BugproneIdenticalExpressionsRule : public Rule {
  public:
    std::string id() const override { return "bugprone/identical-expressions"; }
    std::string title() const override { return "Identical expressions"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override { return "Detects identical variables on both sides of a binary operator."; }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        
        Finder.addMatcher(
            binaryOperator(
                hasAnyOperatorName("==", "!=", "<", "<=", ">", ">=", "-", "/"),
                hasLHS(ignoringParenImpCasts(declRefExpr().bind("lhs"))),
                hasRHS(ignoringParenImpCasts(declRefExpr().bind("rhs")))
            ).bind("op"),
            this
        );
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *LeftExpr = Result.Nodes.getNodeAs<clang::DeclRefExpr>("lhs");
        const auto *RightExpr = Result.Nodes.getNodeAs<clang::DeclRefExpr>("rhs");
        const auto *BinaryOp = Result.Nodes.getNodeAs<clang::BinaryOperator>("op");

        if (LeftExpr == nullptr || RightExpr == nullptr || BinaryOp == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        if (isInSystemHeader(BinaryOp->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        if (LeftExpr && RightExpr && BinaryOp) {
            if (LeftExpr->getDecl() == RightExpr->getDecl()) {
                Finding finding;
                finding.ruleId = id();
                finding.message = "Identical expressions on both sides of a binary operator";
                finding.severity = defaultSeverity();
                finding.category = category();

                auto &sourceManager = *Result.SourceManager;
                finding.file = sourceManager.getFilename(BinaryOp->getExprLoc()).str();
                finding.line = sourceManager.getSpellingLineNumber(BinaryOp->getExprLoc());
                finding.column = sourceManager.getSpellingColumnNumber(BinaryOp->getExprLoc());

                if (!finding.file.empty()) {
                    findings.push_back(finding);
                }
            }
        }
    }
};
} // namespace astharbor
