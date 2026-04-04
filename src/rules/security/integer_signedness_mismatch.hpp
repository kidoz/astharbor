#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityIntegerSignednessMismatchRule : public Rule {
  public:
    std::string id() const override { return "security/integer-signedness-mismatch"; }
    std::string title() const override { return "Integer signedness mismatch"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects comparisons between signed and unsigned integer types, where implicit "
               "conversion can cause negative values to become large positive values.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            binaryOperator(
                hasAnyOperatorName("<", "<=", ">", ">=", "==", "!="),
                hasLHS(expr().bind("cmp_lhs")),
                hasRHS(expr().bind("cmp_rhs")))
                .bind("cmp_op"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *LeftExpr = Result.Nodes.getNodeAs<clang::Expr>("cmp_lhs");
        const auto *RightExpr = Result.Nodes.getNodeAs<clang::Expr>("cmp_rhs");
        const auto *CompareOp = Result.Nodes.getNodeAs<clang::BinaryOperator>("cmp_op");

        if (LeftExpr == nullptr || RightExpr == nullptr || CompareOp == nullptr ||
            Result.SourceManager == nullptr) {
            return;
        }

        if (isInSystemHeader(CompareOp->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        clang::QualType LeftType = LeftExpr->IgnoreParenImpCasts()->getType();
        clang::QualType RightType = RightExpr->IgnoreParenImpCasts()->getType();

        if (!LeftType->isIntegerType() || !RightType->isIntegerType()) {
            return;
        }

        // Skip boolean types — comparing bool to int is not a signedness issue
        if (LeftType->isBooleanType() || RightType->isBooleanType()) {
            return;
        }

        bool LeftSigned = LeftType->isSignedIntegerType();
        bool RightSigned = RightType->isSignedIntegerType();

        if (LeftSigned == RightSigned) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "Comparison between signed and unsigned integers — implicit conversion can cause "
            "negative values to become large positive values (CWE-195)";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(CompareOp->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(CompareOp->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(CompareOp->getExprLoc());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};
} // namespace astharbor
