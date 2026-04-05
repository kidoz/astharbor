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
/// then-block has no non-terminator elements in the reachable path.
///
/// Implemented as a CFG forward reachability query rooted at the
/// IfStmt's true-branch successor: BFS forward from element 0 of the
/// then-block, terminating paths on any reassignment to the checked
/// variable and reporting the first dereference found.
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
        auto pointerVarRef = ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasLocalStorage(), hasType(pointerType())).bind("null_var"))));
        auto nullConstant = ignoringParenImpCasts(
            anyOf(cxxNullPtrLiteralExpr(), integerLiteral(equals(0)),
                  gnuNullExpr()));
        auto equalityCheck = binaryOperator(
            hasOperatorName("=="), hasOperands(pointerVarRef, nullConstant));
        auto notCheck =
            unaryOperator(hasOperatorName("!"), hasUnaryOperand(pointerVarRef));
        Finder.addMatcher(
            ifStmt(hasCondition(anyOf(equalityCheck, notCheck)),
                   hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("null_check_if"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *IfNode = Result.Nodes.getNodeAs<clang::IfStmt>("null_check_if");
        const auto *NullVar = Result.Nodes.getNodeAs<clang::VarDecl>("null_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (IfNode == nullptr || NullVar == nullptr || Func == nullptr ||
            !Func->hasBody() || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(IfNode->getIfLoc(), *Result.SourceManager)) {
            return;
        }

        const clang::CFG *cfg = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfg == nullptr) {
            return;
        }

        // Find the CFG block whose terminator is this IfStmt. Its first
        // successor (succ_begin) is the then-branch — the block entered
        // when the condition evaluated true, i.e. the pointer is null.
        const clang::CFGBlock *ifBlock = nullptr;
        for (const clang::CFGBlock *block : *cfg) {
            if (block == nullptr) {
                continue;
            }
            if (block->getTerminatorStmt() == IfNode) {
                ifBlock = block;
                break;
            }
        }
        if (ifBlock == nullptr || ifBlock->succ_empty()) {
            return;
        }
        const clang::CFGBlock *thenBlock =
            ifBlock->succ_begin()->getReachableBlock();
        if (thenBlock == nullptr) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            thenBlock, 0,
            [&](const clang::Stmt *stmt) {
                return cfg::isAssignmentTo(stmt, NullVar);
            },
            [&](const clang::Stmt *stmt) {
                return findDereference(stmt, NullVar)
                    .value_or(clang::SourceLocation{});
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
    /// Recursively find a dereference of `targetVar` in `stmt`. A
    /// dereference is:
    ///   * `p->field` / `p->method()` — MemberExpr with isArrow
    ///   * `*p`                       — UnaryOperator(UO_Deref)
    ///   * `p[i]`                     — ArraySubscriptExpr
    static std::optional<clang::SourceLocation>
    findDereference(const clang::Stmt *stmt, const clang::VarDecl *targetVar) {
        if (stmt == nullptr) {
            return std::nullopt;
        }
        if (const auto *member = llvm::dyn_cast<clang::MemberExpr>(stmt);
            member != nullptr && member->isArrow() &&
            cfg::isDirectRefTo(member->getBase(), targetVar)) {
            return member->getExprLoc();
        }
        if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(stmt);
            unary != nullptr && unary->getOpcode() == clang::UO_Deref &&
            cfg::isDirectRefTo(unary->getSubExpr(), targetVar)) {
            return unary->getExprLoc();
        }
        if (const auto *subscript = llvm::dyn_cast<clang::ArraySubscriptExpr>(stmt);
            subscript != nullptr &&
            cfg::isDirectRefTo(subscript->getBase(), targetVar)) {
            return subscript->getExprLoc();
        }
        for (const clang::Stmt *child : stmt->children()) {
            if (auto loc = findDereference(child, targetVar)) {
                return loc;
            }
        }
        return std::nullopt;
    }
};

} // namespace astharbor
