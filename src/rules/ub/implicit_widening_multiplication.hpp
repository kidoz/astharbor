#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/ASTContext.h>

namespace astharbor {

/// Detects multiplications of narrow signed integers whose result is
/// implicitly widened to a larger integer type. The multiplication is
/// performed in the narrower type, risking signed overflow (undefined
/// behavior per [expr]/4 and [expr.mul]) before the widening cast.
class UbImplicitWideningMultiplicationRule : public Rule {
  public:
    std::string id() const override { return "ub/implicit-widening-multiplication"; }
    std::string title() const override { return "Implicit widening of multiplication result"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Multiplication result is widened after overflow — cast an operand to the wider "
               "type first.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            implicitCastExpr(
                hasCastKind(clang::CK_IntegralCast),
                hasImplicitDestinationType(isInteger()),
                has(binaryOperator(hasOperatorName("*")).bind("mul")))
                .bind("cast"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Cast = Result.Nodes.getNodeAs<clang::ImplicitCastExpr>("cast");
        const auto *Mul = Result.Nodes.getNodeAs<clang::BinaryOperator>("mul");
        if (Cast == nullptr || Mul == nullptr || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Mul->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        auto &context = *Result.Context;
        clang::QualType destinationType = Cast->getType();
        clang::QualType multiplicationType = Mul->getType();

        if (!destinationType->isIntegerType() || !multiplicationType->isIntegerType()) {
            return;
        }

        unsigned destinationBits = context.getIntWidth(destinationType);
        unsigned multiplicationBits = context.getIntWidth(multiplicationType);
        if (destinationBits <= multiplicationBits) {
            return;
        }

        // Only signed overflow is UB; unsigned wraparound is defined behavior.
        if (!multiplicationType->isSignedIntegerType()) {
            return;
        }

        // Suppress when at least one operand is already a constant that cannot
        // cause overflow — very common false-positive source.
        clang::Expr::EvalResult lhsEval;
        clang::Expr::EvalResult rhsEval;
        bool lhsConstant = Mul->getLHS()->EvaluateAsInt(lhsEval, context);
        bool rhsConstant = Mul->getRHS()->EvaluateAsInt(rhsEval, context);
        if (lhsConstant && rhsConstant) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "Multiplication performed in " + std::to_string(multiplicationBits) +
            "-bit signed type then widened to " + std::to_string(destinationBits) +
            "-bit type; cast an operand first to avoid overflow";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(Mul->getExprLoc());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};

} // namespace astharbor
