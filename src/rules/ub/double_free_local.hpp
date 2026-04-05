#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/ExprCXX.h>
#include <optional>

namespace astharbor {

/// Detects two `delete` calls on the same local pointer variable within a
/// function body, without an intervening reassignment. Per [expr.delete]/4
/// the pointer operand must have come from exactly one prior new-expression,
/// so reusing the same pointer for a second delete is undefined behavior
/// (and typically crashes).
///
/// Implemented as a CFG forward reachability query: BFS forward from
/// the block containing the first delete, treating reassignments as
/// path terminators and a second delete of the same variable on any
/// reachable path as the diagnostic.
class UbDoubleFreeLocalRule : public Rule {
  public:
    std::string id() const override { return "ub/double-free-local"; }
    std::string title() const override { return "Double free of local pointer"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Same local pointer passed to delete twice within a function without "
               "reassignment — undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            cxxDeleteExpr(hasDescendant(declRefExpr(to(varDecl().bind("deleted_var")))),
                          hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("first_delete"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *FirstDelete =
            Result.Nodes.getNodeAs<clang::CXXDeleteExpr>("first_delete");
        const auto *DeletedVar = Result.Nodes.getNodeAs<clang::VarDecl>("deleted_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (FirstDelete == nullptr || DeletedVar == nullptr || Func == nullptr ||
            !Func->hasBody() || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (!DeletedVar->hasLocalStorage()) {
            return;
        }
        if (isInSystemHeader(FirstDelete->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        const clang::CFG *cfg = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfg == nullptr) {
            return;
        }

        auto start = cfg::locateStmt(*cfg, FirstDelete);
        if (!start) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            start->first, start->second,
            [&](const clang::Stmt *stmt) {
                return cfg::isAssignmentTo(stmt, DeletedVar);
            },
            [&](const clang::Stmt *stmt) {
                return findSecondDeleteLocation(stmt, DeletedVar, FirstDelete)
                    .value_or(clang::SourceLocation{});
            });

        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Pointer '" + DeletedVar->getNameAsString() +
                        "' is deleted twice within this function without an intervening "
                        "reassignment — undefined behavior");
    }

  private:
    /// Recursively look for a `CXXDeleteExpr` operating on `targetVar`
    /// that is not `excludedDelete` (the first delete itself).
    static std::optional<clang::SourceLocation>
    findSecondDeleteLocation(const clang::Stmt *stmt, const clang::VarDecl *targetVar,
                             const clang::CXXDeleteExpr *excludedDelete) {
        if (stmt == nullptr || stmt == excludedDelete) {
            return std::nullopt;
        }
        if (const auto *deleteExpr = llvm::dyn_cast<clang::CXXDeleteExpr>(stmt)) {
            if (cfg::isDirectRefTo(deleteExpr->getArgument(), targetVar)) {
                return deleteExpr->getExprLoc();
            }
        }
        for (const clang::Stmt *child : stmt->children()) {
            if (auto loc = findSecondDeleteLocation(child, targetVar, excludedDelete)) {
                return loc;
            }
        }
        return std::nullopt;
    }
};

} // namespace astharbor
