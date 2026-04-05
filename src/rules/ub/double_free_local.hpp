#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/RecursiveASTVisitor.h>

namespace astharbor {

/// Detects two `delete` (or `free`) calls on the same local pointer
/// variable within the same function body, without a reassignment in
/// between. Per [expr.delete]/4 the pointer operand must have come from
/// exactly one prior new-expression, so reusing the same pointer for a
/// second delete is undefined behavior (and typically crashes).
///
/// Like ub/use-after-move this is a Tier 2 rule implemented via a
/// function-body walk with source-location ordering rather than full
/// CFG analysis. It catches straight-line double-deletes and reports the
/// location of the second delete. Heap deletes via multiple aliased
/// pointers are out of scope for this heuristic.
class UbDoubleFreeLocalRule : public Rule {
  public:
    std::string id() const override { return "ub/double-free-local"; }
    std::string title() const override { return "Double free of local pointer"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Same local pointer passed to delete/free twice within a function without "
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
        const auto *Var = Result.Nodes.getNodeAs<clang::VarDecl>("deleted_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (FirstDelete == nullptr || Var == nullptr || Func == nullptr ||
            !Func->hasBody() || Result.SourceManager == nullptr) {
            return;
        }
        if (!Var->hasLocalStorage()) {
            return;
        }
        if (isInSystemHeader(FirstDelete->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        clang::SourceLocation firstEnd =
            sourceManager.getExpansionLoc(FirstDelete->getEndLoc());

        Visitor visitor(Var, firstEnd, sourceManager);
        visitor.TraverseStmt(Func->getBody());

        if (visitor.secondDeleteLoc.isInvalid()) {
            return;
        }

        emitFinding(visitor.secondDeleteLoc, sourceManager,
                    "Pointer '" + Var->getNameAsString() +
                        "' is deleted twice within this function without an intervening "
                        "reassignment — undefined behavior");
    }

  private:
    class Visitor : public clang::RecursiveASTVisitor<Visitor> {
      public:
        Visitor(const clang::VarDecl *var, clang::SourceLocation firstEnd,
                const clang::SourceManager &sourceManager)
            : targetVar(var), firstDeleteEnd(firstEnd), sm(sourceManager) {}

        bool TraverseBinaryOperator(clang::BinaryOperator *op) {
            if (op->isAssignmentOp()) {
                auto *lhs = op->getLHS()->IgnoreParenImpCasts();
                if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(lhs);
                    ref != nullptr && ref->getDecl() == targetVar) {
                    TraverseStmt(op->getRHS());
                    auto loc = sm.getExpansionLoc(op->getExprLoc());
                    if (sm.isBeforeInTranslationUnit(firstDeleteEnd, loc)) {
                        reassignedAfterFirst = true;
                    }
                    return true;
                }
            }
            return clang::RecursiveASTVisitor<Visitor>::TraverseBinaryOperator(op);
        }

        bool VisitCXXDeleteExpr(clang::CXXDeleteExpr *deleteExpr) {
            if (secondDeleteLoc.isValid()) {
                return true;
            }
            if (reassignedAfterFirst) {
                return true;
            }
            auto loc = sm.getExpansionLoc(deleteExpr->getExprLoc());
            // Must be strictly after the first delete.
            if (!sm.isBeforeInTranslationUnit(firstDeleteEnd, loc)) {
                return true;
            }
            // Check whether the delete's argument is the same variable.
            const auto *arg = deleteExpr->getArgument()->IgnoreParenImpCasts();
            const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(arg);
            if (ref != nullptr && ref->getDecl() == targetVar) {
                secondDeleteLoc = loc;
            }
            return true;
        }

        clang::SourceLocation secondDeleteLoc;

      private:
        const clang::VarDecl *targetVar;
        clang::SourceLocation firstDeleteEnd;
        const clang::SourceManager &sm;
        bool reassignedAfterFirst = false;
    };
};

} // namespace astharbor
