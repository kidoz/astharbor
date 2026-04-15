#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

class SecurityStrncpyTruncationRule : public Rule {
  public:
    std::string id() const override { return "security/strncpy-truncation"; }
    std::string title() const override { return "strncpy truncation"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "strncpy(dst, src, sizeof(dst)) may leave dst without a null terminator.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(callExpr(callee(functionDecl(hasAnyName(
                                       "strncpy", "::strncpy", "std::strncpy", "::std::strncpy"))),
                                   argumentCountIs(3))
                              .bind("strncpy_call"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("strncpy_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        const auto *destVar = referencedVar(Call->getArg(0));
        if (destVar == nullptr) {
            return;
        }
        const auto *sizeArg =
            llvm::dyn_cast<clang::UnaryExprOrTypeTraitExpr>(Call->getArg(2)->IgnoreParenImpCasts());
        if (sizeArg == nullptr || sizeArg->getKind() != clang::UETT_SizeOf ||
            sizeArg->isArgumentType()) {
            return;
        }
        if (cfg::findFirstDescendantIf(
                sizeArg->getArgumentExpr(), [destVar](const clang::Stmt *node) {
                    const auto *expr = llvm::dyn_cast<clang::Expr>(node);
                    return expr != nullptr && cfg::isDirectRefTo(expr, destVar);
                }) == nullptr) {
            return;
        }
        emitFinding(Call->getExprLoc(), *Result.SourceManager,
                    "strncpy() with sizeof(destination) can produce an unterminated truncated "
                    "string — reserve space for '\\0' and terminate explicitly");
    }

  private:
    static const clang::VarDecl *referencedVar(const clang::Expr *expr) {
        if (expr == nullptr) {
            return nullptr;
        }
        expr = expr->IgnoreParenImpCasts();
        if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(expr)) {
            return llvm::dyn_cast<clang::VarDecl>(ref->getDecl());
        }
        if (const auto *subscript = llvm::dyn_cast<clang::ArraySubscriptExpr>(expr)) {
            return referencedVar(subscript->getBase());
        }
        if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(expr);
            unary != nullptr && unary->getOpcode() == clang::UO_AddrOf) {
            return referencedVar(unary->getSubExpr());
        }
        return nullptr;
    }
};

} // namespace astharbor
