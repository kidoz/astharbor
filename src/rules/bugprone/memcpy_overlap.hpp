#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

class BugproneMemcpyOverlapRule : public Rule {
  public:
    std::string id() const override { return "bugprone/memcpy-overlap"; }
    std::string title() const override { return "memcpy overlap"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "memcpy() source and destination are obvious regions of the same object; use "
               "memmove().";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(callExpr(callee(functionDecl(hasAnyName("memcpy", "::memcpy",
                                                                  "std::memcpy", "::std::memcpy"))),
                                   argumentCountIs(3))
                              .bind("memcpy_call"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("memcpy_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        const clang::VarDecl *dstBase = baseVar(Call->getArg(0));
        const clang::VarDecl *srcBase = baseVar(Call->getArg(1));
        if (dstBase == nullptr || srcBase == nullptr || dstBase != srcBase) {
            return;
        }
        emitFinding(Call->getExprLoc(), *Result.SourceManager,
                    "memcpy() source and destination refer to the same object '" +
                        dstBase->getNameAsString() + "' — use memmove() for overlapping regions");
    }

  private:
    static const clang::VarDecl *baseVar(const clang::Expr *expr) {
        if (expr == nullptr) {
            return nullptr;
        }
        expr = expr->IgnoreParenImpCasts();
        if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(expr)) {
            return llvm::dyn_cast<clang::VarDecl>(ref->getDecl());
        }
        if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(expr);
            unary != nullptr && unary->getOpcode() == clang::UO_AddrOf) {
            return baseVar(unary->getSubExpr());
        }
        if (const auto *subscript = llvm::dyn_cast<clang::ArraySubscriptExpr>(expr)) {
            return baseVar(subscript->getBase());
        }
        return nullptr;
    }
};

} // namespace astharbor
