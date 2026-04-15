#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

/// Detects `malloc` / `realloc` calls whose size argument is an
/// unsigned multiplication that can wrap `size_t` at runtime:
///
///     void *p = malloc(n * sizeof(Thing));       // n is size_t
///     void *q = realloc(old, count * elem_size); // both unsigned
///
/// Signed operands are deliberately skipped — those are owned by
/// security/signed-arith-in-alloc, which flags the undefined-behavior
/// aspect of signed overflow. Both-operands-constant multiplications
/// are also skipped because the compiler folds them at compile time.
/// The recommended fix is `calloc(n, sizeof(Thing))` (POSIX requires
/// calloc to detect the overflow and return NULL) or an explicit
/// `n > SIZE_MAX / sizeof(Thing)` guard.
class SecurityIntegerOverflowInMallocRule : public Rule {
  public:
    std::string id() const override { return "security/integer-overflow-in-malloc"; }
    std::string title() const override { return "Integer overflow in malloc/realloc size"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Allocation size is a multiplication with a non-constant operand — the "
               "product can overflow size_t, producing an undersized buffer.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        auto multiplication =
            ignoringParenImpCasts(binaryOperator(hasOperatorName("*")).bind("mul_expr"));

        // malloc(size) — include unqualified, ::-prefixed, and std:: spellings
        // for parity with security/signed-arith-in-alloc.
        Finder.addMatcher(callExpr(callee(functionDecl(hasAnyName("malloc", "::malloc",
                                                                  "std::malloc", "::std::malloc"))),
                                   hasArgument(0, multiplication))
                              .bind("alloc_call"),
                          this);
        // realloc(ptr, size)
        Finder.addMatcher(callExpr(callee(functionDecl(hasAnyName(
                                       "realloc", "::realloc", "std::realloc", "::std::realloc"))),
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
        const clang::Expr *lhs = Mul->getLHS()->IgnoreParenImpCasts();
        const clang::Expr *rhs = Mul->getRHS()->IgnoreParenImpCasts();
        // Guard against dependent-type / recovery-state expressions
        // where `getType()` can return a null QualType. Dereferencing
        // via operator-> would segfault on complex templated code
        // (which is exactly what self-analysis of the analyzer itself
        // hits on LLVM 18 CI).
        const clang::QualType lhsType = lhs->getType();
        const clang::QualType rhsType = rhs->getType();
        if (lhsType.isNull() || rhsType.isNull()) {
            return;
        }
        // Classify each operand as constant or not. Constant sides
        // (`4`, `sizeof(T)`, `M_CONST`) never cause runtime overflow
        // on their own and never represent "signed user input" even
        // when their type is `int`, so they should not poison the
        // signed-operand check below.
        clang::Expr::EvalResult lhsEval;
        clang::Expr::EvalResult rhsEval;
        const bool lhsConstant = lhs->EvaluateAsInt(lhsEval, *Result.Context);
        const bool rhsConstant = rhs->EvaluateAsInt(rhsEval, *Result.Context);
        if (lhsConstant && rhsConstant) {
            return; // compile-time-foldable; cannot overflow at runtime
        }
        // Signed non-constant operands are owned by
        // security/signed-arith-in-alloc, which flags the UB aspect.
        // This rule covers the complementary case: a non-constant
        // UNSIGNED multiplication whose wraparound produces an
        // undersized buffer (defined behavior, still a bug).
        if ((!lhsConstant && lhsType->isSignedIntegerType()) ||
            (!rhsConstant && rhsType->isSignedIntegerType())) {
            return;
        }

        const clang::FunctionDecl *callee = Call->getDirectCallee();
        const std::string calleeName = callee != nullptr ? callee->getNameAsString() : "malloc";
        emitFinding(Mul->getExprLoc(), *Result.SourceManager,
                    "Allocation size in '" + calleeName +
                        "' is a multiplication with a non-constant operand and can "
                        "overflow size_t — use calloc() or add an explicit overflow "
                        "check");
    }
};

} // namespace astharbor
