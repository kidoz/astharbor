#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <optional>

namespace astharbor {

/// Detects a pointer dereference on a path where the same pointer was
/// just confirmed null. The canonical bug shape is
///
///     if (p == nullptr) {
///         p->foo();           // undefined behavior
///     }
///
/// Also catches the `if (!p)` and `if (p == 0)` spellings. Early-return
/// guards (`if (!p) return;`) are naturally excluded because the CFG's
/// then-block has no non-terminator elements on the path from the
/// IfStmt's true-branch successor to the return.
class UbNullDerefAfterCheckRule : public Rule {
  public:
    std::string id() const override { return "ub/null-deref-after-check"; }
    std::string title() const override { return "Null dereference after null check"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Pointer is dereferenced on a path where it was just confirmed null — "
               "undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // Restrict to local pointer variables so `x == 0` on an int is
        // never matched. The null constant can be `nullptr`, a literal
        // `0`, or Clang's gnu null expression (the internal form of
        // `NULL` when the platform defines it as __null).
        auto pointerVarRef = ignoringParenImpCasts(
            declRefExpr(to(varDecl(hasLocalStorage(), hasType(pointerType())).bind("null_var"))));
        auto nullConstant = ignoringParenImpCasts(
            anyOf(cxxNullPtrLiteralExpr(), integerLiteral(equals(0)), gnuNullExpr()));
        auto equalityCheck =
            binaryOperator(hasOperatorName("=="), hasOperands(pointerVarRef, nullConstant));
        auto notCheck = unaryOperator(hasOperatorName("!"), hasUnaryOperand(pointerVarRef));
        Finder.addMatcher(ifStmt(hasCondition(anyOf(equalityCheck, notCheck)),
                                 hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                              .bind("null_check_if"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *IfNode = Result.Nodes.getNodeAs<clang::IfStmt>("null_check_if");
        const auto *NullVar = Result.Nodes.getNodeAs<clang::VarDecl>("null_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (IfNode == nullptr || NullVar == nullptr || Func == nullptr || !Func->hasBody() ||
            Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(IfNode->getIfLoc(), *Result.SourceManager)) {
            return;
        }

        const clang::CFG *cfg = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfg == nullptr) {
            return;
        }
        const clang::CFGBlock *ifBlock = cfg::locateTerminator(Func, IfNode);
        if (ifBlock == nullptr || ifBlock->succ_empty()) {
            return;
        }
        // CFGBlock::succs() yields [then-block, else-block] for an
        // if-terminator; the then-block is where the pointer is null.
        const clang::CFGBlock *thenBlock = ifBlock->succ_begin()->getReachableBlock();
        if (thenBlock == nullptr) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            thenBlock, 0,
            [&](const clang::Stmt *stmt) { return cfg::isAssignmentTo(stmt, NullVar); },
            [&](const clang::Stmt *stmt) {
                if (const auto *deref = findDereference(stmt, NullVar)) {
                    return deref->getBeginLoc();
                }
                return clang::SourceLocation{};
            });

        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Pointer '" + NullVar->getNameAsString() +
                        "' is dereferenced on a path where it was just confirmed null "
                        "— undefined behavior");
    }

  private:
    /// Search `stmt`'s subtree for a dereference of `targetVar` in any
    /// of these three shapes: `targetVar->field` (arrow member access),
    /// `*targetVar` (unary deref), or `targetVar[i]` (array subscript).
    static const clang::Stmt *findDereference(const clang::Stmt *stmt,
                                              const clang::VarDecl *targetVar) {
        return cfg::findFirstDescendantIf(stmt, [targetVar](const clang::Stmt *node) {
            if (const auto *member = llvm::dyn_cast<clang::MemberExpr>(node)) {
                return member->isArrow() && cfg::isDirectRefTo(member->getBase(), targetVar);
            }
            if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(node)) {
                return unary->getOpcode() == clang::UO_Deref &&
                       cfg::isDirectRefTo(unary->getSubExpr(), targetVar);
            }
            if (const auto *subscript = llvm::dyn_cast<clang::ArraySubscriptExpr>(node)) {
                return cfg::isDirectRefTo(subscript->getBase(), targetVar);
            }
            return false;
        });
    }
};

} // namespace astharbor
