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
        Finder.addMatcher(
            arraySubscriptExpr(
                hasBase(ignoringParenImpCasts(
                    declRefExpr(to(varDecl(hasType(constantArrayType())).bind("array_var"))))),
                hasIndex(ignoringParenImpCasts(integerLiteral().bind("index_literal"))))
                .bind("subscript"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Subscript = Result.Nodes.getNodeAs<clang::ArraySubscriptExpr>("subscript");
        const auto *ArrayVar = Result.Nodes.getNodeAs<clang::VarDecl>("array_var");
        const auto *Index = Result.Nodes.getNodeAs<clang::IntegerLiteral>("index_literal");

        if (Subscript == nullptr || ArrayVar == nullptr || Index == nullptr ||
            Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Subscript->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        const auto *ArrType = Result.Context->getAsConstantArrayType(ArrayVar->getType());
        if (ArrType == nullptr) {
            return;
        }
        uint64_t arraySize = ArrType->getSize().getZExtValue();
        llvm::APInt indexValue = Index->getValue();

        bool outOfBounds = false;
        if (indexValue.isNegative()) {
            outOfBounds = true;
        } else if (indexValue.getZExtValue() >= arraySize) {
            outOfBounds = true;
        }

        if (outOfBounds) {
            Finding finding;
            finding.ruleId = id();
            finding.message = "Array index " + std::to_string(indexValue.getSExtValue()) +
                              " is out of bounds for array of size " + std::to_string(arraySize) +
                              " — undefined behavior";
            finding.severity = defaultSeverity();
            finding.category = category();

            auto &sourceManager = *Result.SourceManager;
            auto location = sourceManager.getExpansionLoc(Subscript->getExprLoc());
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
