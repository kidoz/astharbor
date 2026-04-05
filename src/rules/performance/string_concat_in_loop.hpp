#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/ExprCXX.h>

namespace astharbor {

/// Detects `s = s + other` inside a loop where `s` is a `std::string`
/// (or any `std::basic_string` specialization). Each iteration
/// constructs a fresh temporary concatenation and copy-assigns it
/// back into `s` — quadratic work in the final string length.
///
/// Only the direct shape `s = s + X` is flagged (one argument of the
/// top-level `+` must be `s` itself). Nested chains like
/// `s = s + a + b` are not matched — programmers writing those tend
/// to already use `+=`, and the matcher restriction keeps false
/// positives at zero on the patterns we've seen.
class PerformanceStringConcatInLoopRule : public Rule {
  public:
    std::string id() const override { return "performance/string-concat-in-loop"; }
    std::string title() const override { return "Quadratic string concatenation in loop"; }
    std::string category() const override { return "performance"; }
    std::string summary() const override {
        return "`s = s + other` inside a loop is quadratic — use `s += other` instead.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // Match std::basic_string regardless of inline namespace
        // (libc++ wraps it in `std::__1::`). `hasName("basic_string")`
        // with no qualifiers matches any class named basic_string in
        // any namespace, which is precise enough in practice — no
        // other standard library type shares the name.
        auto stringType = hasType(hasUnqualifiedDesugaredType(recordType(
            hasDeclaration(cxxRecordDecl(hasName("basic_string"))))));
        auto targetVarRef = declRefExpr(
            to(varDecl(stringType).bind("target_var")));
        auto sameVarRef = declRefExpr(
            to(varDecl(equalsBoundNode("target_var"))));
        // `ignoringImplicit` (not `ignoringParenImpCasts`) is required on
        // the RHS because `std::string operator+` returns a temporary
        // that is wrapped in `MaterializeTemporaryExpr` /
        // `CXXBindTemporaryExpr` before being passed to `operator=`.
        Finder.addMatcher(
            cxxOperatorCallExpr(
                hasOverloadedOperatorName("="),
                hasArgument(0, targetVarRef),
                hasArgument(1, ignoringImplicit(cxxOperatorCallExpr(
                                   hasOverloadedOperatorName("+"),
                                   hasAnyArgument(ignoringParenImpCasts(sameVarRef))))),
                hasAncestor(stmt(anyOf(forStmt(), whileStmt(), doStmt(),
                                        cxxForRangeStmt()))))
                .bind("bad_concat"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *BadConcat =
            Result.Nodes.getNodeAs<clang::CXXOperatorCallExpr>("bad_concat");
        const auto *TargetVar = Result.Nodes.getNodeAs<clang::VarDecl>("target_var");
        if (BadConcat == nullptr || TargetVar == nullptr ||
            Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(BadConcat->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        const std::string name = TargetVar->getNameAsString();
        emitFinding(BadConcat->getExprLoc(), *Result.SourceManager,
                    "Quadratic string concatenation '" + name + " = " + name +
                        " + …' inside a loop — use '" + name + " += …' instead");
    }
};

} // namespace astharbor
