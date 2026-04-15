#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>
#include <clang/AST/Type.h>

namespace astharbor {

/// Detects accesses to fixed-size arrays with a constant integer index
/// that is out of bounds (>= array size, or < 0).
/// Out-of-bounds pointer arithmetic is undefined behavior per [expr.add]/4.
class UbStaticArrayOobConstantRule : public Rule {
  public:
    std::string id() const override { return "ub/static-array-oob-constant"; }
    std::string title() const override { return "Static array out-of-bounds access"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Array subscript with constant index out of bounds — undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // Evaluating the index as a constant expression via `EvaluateAsInt`
        // lets us catch both literal indices (`arr[10]`) and folded negative
        // forms (`arr[-1]`, which appears in the AST as a unary operator
        // wrapping an integer literal).
        Finder.addMatcher(
            arraySubscriptExpr(hasBase(ignoringParenImpCasts(declRefExpr(
                                   to(varDecl(hasType(constantArrayType())).bind("array_var"))))))
                .bind("subscript"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Subscript = Result.Nodes.getNodeAs<clang::ArraySubscriptExpr>("subscript");
        const auto *ArrayVar = Result.Nodes.getNodeAs<clang::VarDecl>("array_var");
        if (Subscript == nullptr || ArrayVar == nullptr) {
            return;
        }

        auto &context = *Result.Context;
        const auto *ArrType = context.getAsConstantArrayType(ArrayVar->getType());
        if (ArrType == nullptr) {
            return;
        }

        clang::Expr::EvalResult eval;
        if (!Subscript->getIdx()->EvaluateAsInt(eval, context)) {
            return;
        }
        llvm::APSInt indexValue = eval.Val.getInt();
        int64_t signedIndex = indexValue.getExtValue();
        uint64_t arraySize = ArrType->getSize().getZExtValue();
        if (signedIndex >= 0 && static_cast<uint64_t>(signedIndex) < arraySize) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        emitFinding(Subscript->getExprLoc(), sourceManager,
                    "Array index " + std::to_string(signedIndex) +
                        " is out of bounds for array of size " + std::to_string(arraySize) +
                        " — undefined behavior");
    }
};

} // namespace astharbor
