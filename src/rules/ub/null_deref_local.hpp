#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

class UbNullDerefLocalRule : public Rule {
  public:
    std::string id() const override { return "ub/null-deref-local"; }
    std::string title() const override { return "Local null dereference"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "A local pointer initialized to null is dereferenced before reassignment.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(varDecl(hasLocalStorage(), hasType(pointerType()),
                                  hasInitializer(expr().bind("init_expr")),
                                  hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                              .bind("null_var"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *NullVar = Result.Nodes.getNodeAs<clang::VarDecl>("null_var");
        const auto *InitExpr = Result.Nodes.getNodeAs<clang::Expr>("init_expr");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (NullVar == nullptr || InitExpr == nullptr || Func == nullptr || !Func->hasBody() ||
            Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (!isNullLiteral(InitExpr) ||
            isInSystemHeader(NullVar->getLocation(), *Result.SourceManager)) {
            return;
        }
        const clang::CFG *cfg = cfg::getOrBuildCfg(Func, *Result.Context);
        if (cfg == nullptr) {
            return;
        }
        auto start = cfg::locateDecl(Func, NullVar);
        if (!start) {
            return;
        }
        auto reportLoc = cfg::forwardReachable(
            start->first, start->second + 1,
            [&](const clang::Stmt *stmt) { return cfg::isAssignmentTo(stmt, NullVar); },
            [&](const clang::Stmt *stmt) {
                return findDerefLocation(stmt, NullVar).value_or(clang::SourceLocation{});
            });
        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Local pointer '" + NullVar->getNameAsString() +
                        "' is initialized to null and dereferenced before reassignment");
    }

  private:
    static bool isNullLiteral(const clang::Expr *expr) {
        if (expr == nullptr) {
            return false;
        }
        expr = expr->IgnoreParenImpCasts();
        if (llvm::isa<clang::CXXNullPtrLiteralExpr>(expr) || llvm::isa<clang::GNUNullExpr>(expr)) {
            return true;
        }
        if (const auto *literal = llvm::dyn_cast<clang::IntegerLiteral>(expr)) {
            return literal->getValue() == 0;
        }
        return false;
    }

    static std::optional<clang::SourceLocation> findDerefLocation(const clang::Stmt *stmt,
                                                                  const clang::VarDecl *targetVar) {
        const clang::Stmt *found =
            cfg::findFirstDescendantIf(stmt, [targetVar](const clang::Stmt *node) {
                if (const auto *member = llvm::dyn_cast<clang::MemberExpr>(node);
                    member != nullptr && member->isArrow() &&
                    cfg::isDirectRefTo(member->getBase(), targetVar)) {
                    return true;
                }
                if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(node);
                    unary != nullptr && unary->getOpcode() == clang::UO_Deref &&
                    cfg::isDirectRefTo(unary->getSubExpr(), targetVar)) {
                    return true;
                }
                if (const auto *subscript = llvm::dyn_cast<clang::ArraySubscriptExpr>(node);
                    subscript != nullptr && cfg::isDirectRefTo(subscript->getBase(), targetVar)) {
                    return true;
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
