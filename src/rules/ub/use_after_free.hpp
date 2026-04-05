#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <optional>

namespace astharbor {

/// Detects use-after-free of a local pointer within a single function:
///
///     void *p = malloc(n);
///     free(p);
///     read_into(p, n);             // undefined behavior
///
/// Per CERT MEM30-C and CWE-416, reading or writing through a freed
/// pointer is undefined behavior and one of the most exploited CVE
/// classes. The rule is the direct sibling of `ub/double-free-local`
/// but scoped to the C `free()` family (for `delete`, see
/// `ub/double-free-local` and future use-after-delete work).
///
/// Implemented as a CFG forward reachability query: BFS from the CFG
/// element that contains the first `free(p)` call, terminating each
/// path on any reassignment to `p` and reporting the first reachable
/// "use" of `p`. A use is:
///
///   * a dereference via `*p`, `p->field`, or `p[i]`;
///   * `p` passed as an argument to another call.
///
/// Plain comparison (`p == nullptr`) and taking the address (`&p`) are
/// intentionally not flagged — they're common defensive idioms and
/// the signal-to-noise ratio isn't worth it at this pass.
class UbUseAfterFreeRule : public Rule {
  public:
    std::string id() const override { return "ub/use-after-free"; }
    std::string title() const override { return "Use after free"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Local pointer is dereferenced or passed to another call after free() "
               "without an intervening reassignment — undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(
                callee(functionDecl(hasAnyName("free", "::free", "std::free",
                                                 "::std::free"))),
                hasArgument(0, ignoringParenImpCasts(declRefExpr(to(
                                   varDecl(hasLocalStorage(),
                                            hasType(pointerType()))
                                       .bind("freed_var"))))),
                hasAncestor(
                    functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("free_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *FreeCall = Result.Nodes.getNodeAs<clang::CallExpr>("free_call");
        const auto *FreedVar = Result.Nodes.getNodeAs<clang::VarDecl>("freed_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (FreeCall == nullptr || FreedVar == nullptr || Func == nullptr ||
            !Func->hasBody() || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(FreeCall->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        const clang::CFG *cfg = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfg == nullptr) {
            return;
        }

        auto start = cfg::locateStmt(Func, FreeCall);
        if (!start) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            start->first, start->second + 1,
            [&](const clang::Stmt *stmt) {
                return cfg::isAssignmentTo(stmt, FreedVar);
            },
            [&](const clang::Stmt *stmt) {
                return findUseLocation(stmt, FreedVar, FreeCall)
                    .value_or(clang::SourceLocation{});
            });

        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Pointer '" + FreedVar->getNameAsString() +
                        "' is used after free() without an intervening "
                        "reassignment — undefined behavior");
    }

  private:
    /// Search `stmt`'s subtree for a use of `targetVar` that is not
    /// `excludedCall` (the `free` call itself). A "use" is a
    /// dereference (arrow member, unary deref, subscript) or the var
    /// being passed as an argument to another call.
    static std::optional<clang::SourceLocation>
    findUseLocation(const clang::Stmt *stmt, const clang::VarDecl *targetVar,
                    const clang::CallExpr *excludedCall) {
        const clang::Stmt *found = cfg::findFirstDescendantIf(
            stmt, [targetVar, excludedCall](const clang::Stmt *node) {
                if (const auto *member = llvm::dyn_cast<clang::MemberExpr>(node);
                    member != nullptr && member->isArrow() &&
                    cfg::isDirectRefTo(member->getBase(), targetVar)) {
                    return true;
                }
                if (const auto *unary =
                        llvm::dyn_cast<clang::UnaryOperator>(node);
                    unary != nullptr && unary->getOpcode() == clang::UO_Deref &&
                    cfg::isDirectRefTo(unary->getSubExpr(), targetVar)) {
                    return true;
                }
                if (const auto *subscript =
                        llvm::dyn_cast<clang::ArraySubscriptExpr>(node);
                    subscript != nullptr &&
                    cfg::isDirectRefTo(subscript->getBase(), targetVar)) {
                    return true;
                }
                if (const auto *call = llvm::dyn_cast<clang::CallExpr>(node);
                    call != nullptr && call != excludedCall) {
                    for (unsigned index = 0; index < call->getNumArgs(); ++index) {
                        if (cfg::isDirectRefTo(call->getArg(index), targetVar)) {
                            return true;
                        }
                    }
                }
                return false;
            });
        if (found == nullptr) {
            return std::nullopt;
        }
        return found->getBeginLoc();
    }
};

} // namespace astharbor
