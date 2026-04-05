#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>
#include <llvm/ADT/SmallString.h>

namespace astharbor {

/// Detects shift operations where the right operand is >= the bit width
/// of the promoted left operand type. This is undefined behavior per [expr.shift]/1.
class UbShiftPastBitwidthRule : public Rule {
  public:
    std::string id() const override { return "ub/shift-past-bitwidth"; }
    std::string title() const override { return "Shift past type bit width"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Shift amount >= bit width of the type — undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            binaryOperator(hasAnyOperatorName("<<", ">>", "<<=", ">>=")).bind("shift_op"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Op = Result.Nodes.getNodeAs<clang::BinaryOperator>("shift_op");
        if (Op == nullptr || Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Op->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        // Get the bit width of the promoted left operand type
        clang::QualType leftType = Op->getLHS()->IgnoreParenImpCasts()->getType();
        if (!leftType->isIntegerType()) {
            return;
        }
        unsigned bitWidth = Result.Context->getIntWidth(leftType);

        // Try to evaluate the right operand as a constant integer
        const clang::Expr *rightOperand = Op->getRHS()->IgnoreParenImpCasts();
        clang::Expr::EvalResult evalResult;
        if (!rightOperand->EvaluateAsInt(evalResult, *Result.Context)) {
            return;
        }
        llvm::APSInt shiftAmount = evalResult.Val.getInt();

        // Skip negative shifts (handled by shift-by-negative rule)
        if (shiftAmount.isNegative()) {
            return;
        }

        if (shiftAmount.getZExtValue() >= bitWidth) {
            llvm::SmallString<16> amountStr;
            shiftAmount.toString(amountStr, 10);
            Finding finding;
            finding.ruleId = id();
            finding.message = "Shift amount (" + std::string(amountStr.c_str()) +
                              ") >= bit width of type (" + std::to_string(bitWidth) +
                              ") — undefined behavior";
            finding.severity = defaultSeverity();
            finding.category = category();

            auto &sourceManager = *Result.SourceManager;
            auto location = sourceManager.getExpansionLoc(Op->getExprLoc());
            finding.file = sourceManager.getFilename(location).str();
            finding.line = sourceManager.getSpellingLineNumber(location);
            finding.column = sourceManager.getSpellingColumnNumber(location);

            if (!finding.file.empty()) {
                findings.push_back(finding);
            }
        }
    }
};

} // namespace astharbor
