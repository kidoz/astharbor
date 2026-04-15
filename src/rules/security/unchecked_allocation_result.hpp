#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <clang/AST/ParentMapContext.h>

namespace astharbor {

class SecurityUncheckedAllocationResultRule : public Rule {
  public:
    std::string id() const override { return "security/unchecked-allocation-result"; }
    std::string title() const override { return "Unchecked allocation result"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "A local pointer returned from malloc/calloc/realloc or nothrow new is used without "
               "an obvious null check.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        auto allocCall = callExpr(callee(functionDecl(hasAnyName(
            "malloc", "calloc", "realloc", "::malloc", "::calloc", "::realloc", "std::malloc",
            "std::calloc", "std::realloc", "::std::malloc", "::std::calloc", "::std::realloc"))));
        Finder.addMatcher(varDecl(hasLocalStorage(), hasType(pointerType()),
                                  hasInitializer(expr(hasDescendant(allocCall.bind("alloc_call")))),
                                  hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                              .bind("alloc_var"),
                          this);
        Finder.addMatcher(
            binaryOperator(
                isAssignmentOperator(),
                hasLHS(ignoringParenImpCasts(declRefExpr(
                    to(varDecl(hasLocalStorage(), hasType(pointerType())).bind("alloc_var"))))),
                hasRHS(expr(hasDescendant(allocCall.bind("alloc_call")))),
                hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("alloc_assignment"),
            this);
        Finder.addMatcher(
            varDecl(
                hasLocalStorage(), hasType(pointerType()),
                hasInitializer(
                    cxxNewExpr(anyOf(hasDescendant(declRefExpr(to(varDecl(hasName("nothrow"))))),
                                     hasDescendant(declRefExpr(to(valueDecl(hasName("nothrow")))))))
                        .bind("nothrow_new")),
                hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("alloc_var"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *AllocVar = Result.Nodes.getNodeAs<clang::VarDecl>("alloc_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (AllocVar == nullptr || Func == nullptr || !Func->hasBody() ||
            Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(AllocVar->getLocation(), *Result.SourceManager)) {
            return;
        }
        if (containsNullCheck(Func->getBody(), AllocVar)) {
            return;
        }
        if (findUnsafeUse(Func->getBody(), AllocVar) == nullptr) {
            return;
        }
        emitFinding(AllocVar->getLocation(), *Result.SourceManager,
                    "Allocation result stored in '" + AllocVar->getNameAsString() +
                        "' is used without an obvious null check");
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

    static bool containsNullCheck(const clang::Stmt *stmt, const clang::VarDecl *targetVar) {
        return cfg::findFirstDescendantIf(stmt, [targetVar](const clang::Stmt *node) {
                   if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(node);
                       unary != nullptr && unary->getOpcode() == clang::UO_LNot &&
                       cfg::isDirectRefTo(unary->getSubExpr(), targetVar)) {
                       return true;
                   }
                   if (const auto *binary = llvm::dyn_cast<clang::BinaryOperator>(node);
                       binary != nullptr && (binary->getOpcode() == clang::BO_EQ ||
                                             binary->getOpcode() == clang::BO_NE)) {
                       return (cfg::isDirectRefTo(binary->getLHS(), targetVar) &&
                               isNullLiteral(binary->getRHS())) ||
                              (cfg::isDirectRefTo(binary->getRHS(), targetVar) &&
                               isNullLiteral(binary->getLHS()));
                   }
                   return false;
               }) != nullptr;
    }

    static const clang::Stmt *findUnsafeUse(const clang::Stmt *stmt,
                                            const clang::VarDecl *targetVar) {
        return cfg::findFirstDescendantIf(stmt, [targetVar](const clang::Stmt *node) {
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
    }
};

} // namespace astharbor
