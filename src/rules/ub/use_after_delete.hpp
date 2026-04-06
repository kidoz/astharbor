#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/ExprCXX.h>
#include <optional>

namespace astharbor {

/// Detects use of a local pointer after `delete` without reassignment.
/// The C++ counterpart of `ub/use-after-free`; same CFG reachability
/// approach, same "use" definition (deref, member access, subscript,
/// or passed as a call argument).
class UbUseAfterDeleteRule : public Rule {
  public:
    std::string id() const override { return "ub/use-after-delete"; }
    std::string title() const override { return "Use after delete"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Local pointer used after delete without reassignment — "
               "undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            cxxDeleteExpr(
                hasDescendant(declRefExpr(to(
                    varDecl(hasLocalStorage()).bind("deleted_var")))),
                hasAncestor(
                    functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("delete_expr"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *DeleteExpr =
            Result.Nodes.getNodeAs<clang::CXXDeleteExpr>("delete_expr");
        const auto *DeletedVar =
            Result.Nodes.getNodeAs<clang::VarDecl>("deleted_var");
        const auto *Func =
            Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (DeleteExpr == nullptr || DeletedVar == nullptr ||
            Func == nullptr || !Func->hasBody() ||
            Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(DeleteExpr->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        const clang::CFG *cfgPtr = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfgPtr == nullptr) {
            return;
        }
        auto start = cfg::locateStmt(Func, DeleteExpr);
        if (!start) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            start->first, start->second + 1,
            [&](const clang::Stmt *stmt) {
                return cfg::isAssignmentTo(stmt, DeletedVar);
            },
            [&](const clang::Stmt *stmt) -> clang::SourceLocation {
                const clang::Stmt *found = cfg::findFirstDescendantIf(
                    stmt,
                    [DeletedVar, DeleteExpr](const clang::Stmt *node) {
                        if (node == DeleteExpr) {
                            return false;
                        }
                        if (const auto *member =
                                llvm::dyn_cast<clang::MemberExpr>(node);
                            member != nullptr && member->isArrow() &&
                            cfg::isDirectRefTo(member->getBase(), DeletedVar)) {
                            return true;
                        }
                        if (const auto *unary =
                                llvm::dyn_cast<clang::UnaryOperator>(node);
                            unary != nullptr &&
                            unary->getOpcode() == clang::UO_Deref &&
                            cfg::isDirectRefTo(unary->getSubExpr(), DeletedVar)) {
                            return true;
                        }
                        if (const auto *sub =
                                llvm::dyn_cast<clang::ArraySubscriptExpr>(node);
                            sub != nullptr &&
                            cfg::isDirectRefTo(sub->getBase(), DeletedVar)) {
                            return true;
                        }
                        if (const auto *call =
                                llvm::dyn_cast<clang::CallExpr>(node);
                            call != nullptr) {
                            for (unsigned idx = 0; idx < call->getNumArgs();
                                 ++idx) {
                                if (cfg::isDirectRefTo(call->getArg(idx),
                                                        DeletedVar)) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    });
                return found != nullptr ? found->getBeginLoc()
                                        : clang::SourceLocation{};
            });

        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Pointer '" + DeletedVar->getNameAsString() +
                        "' is used after delete without reassignment — "
                        "undefined behavior");
    }
};

} // namespace astharbor
