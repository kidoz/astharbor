#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>
#include <llvm/ADT/SmallString.h>

namespace astharbor {

/// Detects shift operations where the right operand is a negative value.
/// Shifting by a negative amount is undefined behavior per [expr.shift]/1.
class UbShiftByNegativeRule : public Rule {
  public:
    std::string id() const override { return "ub/shift-by-negative"; }
    std::string title() const override { return "Shift by negative amount"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Shift by a negative amount — undefined behavior.";
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

        const clang::Expr *rightOperand = Op->getRHS()->IgnoreParenImpCasts();
        clang::Expr::EvalResult evalResult;
        if (!rightOperand->EvaluateAsInt(evalResult, *Result.Context)) {
            return;
        }
        llvm::APSInt shiftAmount = evalResult.Val.getInt();
        if (shiftAmount.isNegative()) {
            llvm::SmallString<16> amountStr;
            shiftAmount.toString(amountStr, 10);
            Finding finding;
            finding.ruleId = id();
            finding.message = "Shift by negative amount (" + std::string(amountStr.c_str()) +
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
