#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

class BugproneSizeofExpressionRule : public Rule {
  public:
    std::string id() const override { return "bugprone/sizeof-expression"; }
    std::string title() const override { return "Suspicious sizeof expression"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "sizeof is applied to a pointer expression or this, which is commonly unintended.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(unaryExprOrTypeTraitExpr(ofKind(clang::UETT_SizeOf),
                                                   unless(isExpansionInSystemHeader()))
                              .bind("sizeof_expr"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *SizeofExpr =
            Result.Nodes.getNodeAs<clang::UnaryExprOrTypeTraitExpr>("sizeof_expr");
        if (SizeofExpr == nullptr || Result.SourceManager == nullptr ||
            SizeofExpr->isArgumentType()) {
            return;
        }
        const clang::Expr *argument = SizeofExpr->getArgumentExpr()->IgnoreParenImpCasts();
        if (llvm::isa<clang::CXXThisExpr>(argument)) {
            emitFinding(SizeofExpr->getBeginLoc(), *Result.SourceManager,
                        "sizeof(this) returns the pointer size, not the object size");
            return;
        }
        const clang::QualType type = argument->getType();
        if (!type.isNull() && type->isPointerType()) {
            emitFinding(SizeofExpr->getBeginLoc(), *Result.SourceManager,
                        "sizeof applied to a pointer expression returns the pointer size, not the "
                        "pointee or array size");
        }
    }
};

} // namespace astharbor
