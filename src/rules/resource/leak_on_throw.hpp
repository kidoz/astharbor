#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/ExprCXX.h>

namespace astharbor {

/// Detects raw-new'd local pointers whose owning scope contains a
/// reachable `throw` on a path that has not yet deleted or reassigned
/// the pointer — a classic RAII leak:
///
///     void f() {
///         int *p = new int(42);
///         if (cond) {
///             throw std::runtime_error("bad");   // p leaks
///         }
///         delete p;
///     }
///
/// Scope restrictions for a conservative first pass:
///   * Only raw-pointer locals initialized directly from `new`.
///   * Only `throw`s visible as `CXXThrowExpr` in the AST — calls that
///     may themselves throw are not tracked (would need noexcept
///     analysis and interprocedural reasoning).
///   * Functions containing any `try` block are skipped entirely
///     because the throw may be caught locally and not escape, which
///     would turn into a false positive. The try-block scan is
///     memoized per function via `cfg::functionHasTryBlock` so the
///     cost is paid once regardless of how many raw-new'd locals a
///     function declares.
class ResourceLeakOnThrowRule : public Rule {
  public:
    std::string id() const override { return "resource/leak-on-throw"; }
    std::string title() const override { return "Resource leak on throw path"; }
    std::string category() const override { return "resource"; }
    std::string summary() const override {
        return "Raw-new'd local pointer is not deleted on a reachable throw path — "
               "use a smart pointer or delete before throwing.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            varDecl(hasLocalStorage(), hasType(pointerType()),
                    hasInitializer(ignoringParenImpCasts(cxxNewExpr())),
                    hasAncestor(
                        functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("owning_var"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *OwningVar = Result.Nodes.getNodeAs<clang::VarDecl>("owning_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (OwningVar == nullptr || Func == nullptr || !Func->hasBody() ||
            Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(OwningVar->getLocation(), *Result.SourceManager)) {
            return;
        }
        // Conservative: skip any function containing a `try`, because
        // the throw might be caught locally and not escape. Memoized.
        if (cfg::functionHasTryBlock(Func)) {
            return;
        }

        const clang::CFG *cfg = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfg == nullptr) {
            return;
        }

        auto start = cfg::locateDecl(Func, OwningVar);
        if (!start) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            start->first, start->second + 1,
            [&](const clang::Stmt *stmt) {
                // A path becomes clean if it deletes the variable OR
                // reassigns it (ownership has moved somewhere we can
                // no longer track locally).
                return cfg::isDeleteOf(stmt, OwningVar) ||
                       cfg::isAssignmentTo(stmt, OwningVar);
            },
            [&](const clang::Stmt *stmt) {
                if (const auto *throwExpr =
                        cfg::findFirstDescendant<clang::CXXThrowExpr>(stmt)) {
                    return throwExpr->getThrowLoc();
                }
                return clang::SourceLocation{};
            });

        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Pointer '" + OwningVar->getNameAsString() +
                        "' allocated with new is not deleted before this throw "
                        "— use a smart pointer or delete before throwing");
    }
};

} // namespace astharbor
