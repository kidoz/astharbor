#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/RecursiveASTVisitor.h>

namespace astharbor {

/// Detects uses of a local variable after `std::move(x)` has been called
/// on it, without an intervening reassignment. Per [lib.types.movedfrom]
/// the moved-from object is in a valid-but-unspecified state; methods other
/// than destruction or reassignment are generally a defect. For types like
/// `std::unique_ptr` the subsequent use is actual undefined behavior on
/// dereference.
///
/// This rule uses a function-body walk with source-location ordering rather
/// than full CFG analysis. It catches straight-line code and simple branches
/// where the move dominates the use. It may miss cases where the move only
/// happens on some control-flow paths.
class UbUseAfterMoveRule : public Rule {
  public:
    std::string id() const override { return "ub/use-after-move"; }
    std::string title() const override { return "Use after std::move"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Use of a local variable after std::move without reassignment — the value is "
               "in a valid-but-unspecified state.";
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
            !Func->hasBody() || Result.SourceManager == nullptr) {
            return;
        }
        // Skip globals, parameters in different scopes, and statics — the
        // heuristic is only sound for stack-local variables whose lifetime
        // is confined to the enclosing function body.
        if (!MovedVar->hasLocalStorage()) {
            return;
        }
        if (isInSystemHeader(MoveCall->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        clang::SourceLocation moveLoc = sourceManager.getExpansionLoc(MoveCall->getBeginLoc());
        clang::SourceLocation moveEndLoc = sourceManager.getExpansionLoc(MoveCall->getEndLoc());

        Visitor visitor(MovedVar, moveLoc, moveEndLoc, sourceManager);
        visitor.TraverseStmt(Func->getBody());

        if (visitor.useLocation.isInvalid()) {
            return;
        }

        emitFinding(visitor.useLocation, sourceManager,
                    "Use of '" + MovedVar->getNameAsString() +
                        "' after std::move — the value is in a valid-but-unspecified state; "
                        "reassign before reusing or drop the std::move");
    }

  private:
    /// Walk the enclosing function body, tracking whether we have crossed
    /// the move point. Once past it, the first reference to the moved
    /// variable (and not nested inside the move's own expression) is
    /// reported. Assignments whose LHS is the moved variable are treated
    /// as reinitialization, not as a use, and clear the pending-use state
    /// so code that reassigns before reusing is not flagged.
    class Visitor : public clang::RecursiveASTVisitor<Visitor> {
      public:
        Visitor(const clang::VarDecl *var, clang::SourceLocation moveLoc,
                clang::SourceLocation moveEndLoc, const clang::SourceManager &sourceManager)
            : targetVar(var), moveBegin(moveLoc), moveEnd(moveEndLoc), sm(sourceManager) {}

        // Override traversal for assignments so the LHS is not visited as a
        // generic DeclRefExpr "use" when it is being written to. The RHS is
        // still traversed normally, so uses on the RHS of a reassignment
        // (e.g., `w = transform(w)`) are reported before the reassignment
        // takes effect.
        bool TraverseBinaryOperator(clang::BinaryOperator *op) {
            if (op->isAssignmentOp()) {
                auto *lhs = op->getLHS()->IgnoreParenImpCasts();
                if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(lhs);
                    ref != nullptr && ref->getDecl() == targetVar) {
                    TraverseStmt(op->getRHS());
                    auto loc = sm.getExpansionLoc(op->getExprLoc());
                    if (sm.isBeforeInTranslationUnit(moveEnd, loc)) {
                        reassignedAfterMove = true;
                    }
                    return true;
                }
            }
            return clang::RecursiveASTVisitor<Visitor>::TraverseBinaryOperator(op);
        }

        // Handle overloaded `operator=` calls (class types with user or
        // compiler-generated copy/move assignment). These appear in the AST
        // as CXXOperatorCallExpr, not BinaryOperator.
        bool TraverseCXXOperatorCallExpr(clang::CXXOperatorCallExpr *call) {
            if (call->getOperator() == clang::OO_Equal && call->getNumArgs() == 2) {
                auto *lhs = call->getArg(0)->IgnoreParenImpCasts();
                if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(lhs);
                    ref != nullptr && ref->getDecl() == targetVar) {
                    TraverseStmt(call->getArg(1));
                    auto loc = sm.getExpansionLoc(call->getExprLoc());
                    if (sm.isBeforeInTranslationUnit(moveEnd, loc)) {
                        reassignedAfterMove = true;
                    }
                    return true;
                }
            }
            return clang::RecursiveASTVisitor<Visitor>::TraverseCXXOperatorCallExpr(call);
        }

        bool VisitDeclRefExpr(clang::DeclRefExpr *ref) {
            if (useLocation.isValid()) {
                return true; // already reported the first use
            }
            if (ref->getDecl() != targetVar) {
                return true;
            }
            auto refLoc = sm.getExpansionLoc(ref->getBeginLoc());
            // Skip references before or at the move point (including the
            // move call's own argument).
            if (!sm.isBeforeInTranslationUnit(moveEnd, refLoc)) {
                return true;
            }
            if (reassignedAfterMove) {
                return true;
            }
            useLocation = refLoc;
            return true;
        }

        clang::SourceLocation useLocation;

      private:
        const clang::VarDecl *targetVar;
        clang::SourceLocation moveBegin;
        clang::SourceLocation moveEnd;
        const clang::SourceManager &sm;
        bool reassignedAfterMove = false;
    };
};

} // namespace astharbor
