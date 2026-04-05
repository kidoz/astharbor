#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

/// Detects `malloc` / `realloc` calls whose size argument is a
/// multiplication that could overflow `size_t` at runtime:
///
///     void *p = malloc(n * sizeof(Thing));
///     void *q = realloc(old, count * elem_size);
///
/// If `n` (or `count`) is attacker-controlled and large enough, the
/// multiplication wraps, the allocator returns a buffer far smaller
/// than the caller assumed, and the subsequent writes heap-overflow.
/// This is a classic CVE shape — see CVE-2002-0391, CVE-2008-1687,
/// CVE-2018-12020 and many others.
///
/// The rule flags any `*` sub-expression in the size argument where
/// at least one operand is not a compile-time integer constant. The
/// recommended fix is to use `calloc(n, sizeof(Thing))` (which is
/// required to detect the overflow and return NULL) or to add an
/// explicit `if (n > SIZE_MAX / sizeof(Thing)) …` guard before the
/// allocation. Both-operands-constant multiplications are skipped
/// because the compiler evaluates them at compile time and cannot
/// overflow at runtime.
class SecurityIntegerOverflowInMallocRule : public Rule {
  public:
    std::string id() const override { return "security/integer-overflow-in-malloc"; }
    std::string title() const override {
        return "Integer overflow in malloc/realloc size";
    }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Allocation size is a multiplication with a non-constant operand — the "
               "product can overflow size_t, producing an undersized buffer.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        auto multiplication = ignoringParenImpCasts(
            binaryOperator(hasOperatorName("*")).bind("mul_expr"));

        // malloc(size)
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("malloc", "::std::malloc"))),
                     hasArgument(0, multiplication))
                .bind("alloc_call"),
            this);
        // realloc(ptr, size)
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("realloc", "::std::realloc"))),
                     hasArgument(1, multiplication))
                .bind("alloc_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("alloc_call");
        const auto *Mul = Result.Nodes.getNodeAs<clang::BinaryOperator>("mul_expr");
        if (Call == nullptr || Mul == nullptr || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        // Skip if both operands are compile-time integer constants —
        // the compiler folds them and no runtime overflow is possible.
        const clang::Expr *lhs = Mul->getLHS()->IgnoreParenImpCasts();
        const clang::Expr *rhs = Mul->getRHS()->IgnoreParenImpCasts();
        if (lhs->isIntegerConstantExpr(*Result.Context) &&
            rhs->isIntegerConstantExpr(*Result.Context)) {
            return;
        }

        const clang::FunctionDecl *callee = Call->getDirectCallee();
        const std::string calleeName =
            callee != nullptr ? callee->getNameAsString() : "malloc";
        emitFinding(Mul->getExprLoc(), *Result.SourceManager,
                    "Allocation size in '" + calleeName +
                        "' is a multiplication with a non-constant operand and can "
                        "overflow size_t — use calloc() or add an explicit overflow "
                        "check");
    }
};

} // namespace astharbor
