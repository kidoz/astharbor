#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/ExprCXX.h>
#include <optional>

namespace astharbor {

/// Detects uses of a local variable after `std::move(x)` has been called
/// on it, without an intervening reassignment. Per [lib.types.movedfrom]
/// the moved-from object is in a valid-but-unspecified state; methods
/// other than destruction or reassignment are generally a defect. For
/// types like `std::unique_ptr` the subsequent use is actual undefined
/// behavior on dereference.
///
/// Implemented as a CFG forward reachability query: BFS forward from
/// the block containing the `std::move` call, treating reassignments as
/// path terminators and the first surviving DeclRefExpr to the variable
/// as the diagnostic.
class UbUseAfterMoveRule : public Rule {
  public:
    std::string id() const override { return "ub/use-after-move"; }
    std::string title() const override { return "Use after std::move"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Use of a local variable after std::move without reassignment — the value "
               "is in a valid-but-unspecified state.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(
                callee(functionDecl(hasName("move"),
                                     hasDeclContext(namespaceDecl(hasName("std"))))),
                hasArgument(0, ignoringParenImpCasts(
                                   declRefExpr(to(varDecl().bind("moved_var"))))),
                hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("move_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *MoveCall = Result.Nodes.getNodeAs<clang::CallExpr>("move_call");
        const auto *MovedVar = Result.Nodes.getNodeAs<clang::VarDecl>("moved_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (MoveCall == nullptr || MovedVar == nullptr || Func == nullptr ||
            !Func->hasBody() || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (!MovedVar->hasLocalStorage()) {
            return;
        }
        if (isInSystemHeader(MoveCall->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        const clang::CFG *cfg = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfg == nullptr) {
            return;
        }

        auto start = cfg::locateStmt(*cfg, MoveCall);
        if (!start) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            start->first, start->second + 1,
            [&](const clang::Stmt *stmt) {
                return cfg::isAssignmentTo(stmt, MovedVar);
            },
            [&](const clang::Stmt *stmt) {
                return findUseLocation(stmt, MovedVar, MoveCall)
                    .value_or(clang::SourceLocation{});
            });

        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Use of '" + MovedVar->getNameAsString() +
                        "' after std::move — the value is in a valid-but-unspecified "
                        "state; reassign before reusing or drop the std::move");
    }

  private:
    /// Find the first DeclRefExpr to `targetVar` in `stmt` that is not
    /// part of `excludedCall` (the move call itself).
    static std::optional<clang::SourceLocation>
    findUseLocation(const clang::Stmt *stmt, const clang::VarDecl *targetVar,
                    const clang::CallExpr *excludedCall) {
        if (stmt == nullptr || stmt == excludedCall) {
            return std::nullopt;
        }
        if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(stmt);
            ref != nullptr && ref->getDecl() == targetVar) {
            return ref->getBeginLoc();
        }
        for (const clang::Stmt *child : stmt->children()) {
            if (auto loc = findUseLocation(child, targetVar, excludedCall)) {
                return loc;
            }
        }
        return std::nullopt;
    }
};

} // namespace astharbor
