#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/ExprCXX.h>
#include <optional>

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
///     would turn into a false positive. The vast majority of bug
///     sites are in try-less functions where the throw propagates.
///
/// Uses the shared CFG forward reachability helper: BFS from the
/// variable declaration, terminating paths on `delete p` or on
/// reassignment of `p`, and reporting the first reachable
/// `CXXThrowExpr`.
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
            varDecl(
                hasLocalStorage(), hasType(pointerType()),
                hasInitializer(ignoringParenImpCasts(cxxNewExpr())),
                hasAncestor(functionDecl(isDefinition(),
                                           unless(hasDescendant(cxxTryStmt())))
                                 .bind("enclosing_func")))
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

        const clang::CFG *cfg = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfg == nullptr) {
            return;
        }

        auto start = cfg::locateDecl(*cfg, OwningVar);
        if (!start) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            start->first, start->second + 1,
            [&](const clang::Stmt *stmt) {
                // A path becomes clean if it deletes the variable OR
                // reassigns it (ownership has moved somewhere we can
                // no longer track locally).
                return isDeleteOf(stmt, OwningVar) ||
                       cfg::isAssignmentTo(stmt, OwningVar);
            },
            [&](const clang::Stmt *stmt) {
                return findThrow(stmt).value_or(clang::SourceLocation{});
            });

        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Pointer '" + OwningVar->getNameAsString() +
                        "' allocated with new is not deleted before this throw "
                        "— use a smart pointer or delete before throwing");
    }

  private:
    /// True if `stmt` is `delete targetVar` at the top level. CFG
    /// decomposes compound statements into their own elements, so a
    /// shallow check is enough to catch `delete p;` as its own element.
    static bool isDeleteOf(const clang::Stmt *stmt, const clang::VarDecl *targetVar) {
        const auto *deleteExpr = llvm::dyn_cast<clang::CXXDeleteExpr>(stmt);
        return deleteExpr != nullptr &&
               cfg::isDirectRefTo(deleteExpr->getArgument(), targetVar);
    }

    /// Find a `CXXThrowExpr` anywhere in `stmt`'s subtree.
    static std::optional<clang::SourceLocation>
    findThrow(const clang::Stmt *stmt) {
        if (stmt == nullptr) {
            return std::nullopt;
        }
        if (const auto *throwExpr = llvm::dyn_cast<clang::CXXThrowExpr>(stmt)) {
            return throwExpr->getThrowLoc();
        }
        for (const clang::Stmt *child : stmt->children()) {
            if (auto loc = findThrow(child)) {
                return loc;
            }
        }
        return std::nullopt;
    }
};

} // namespace astharbor
