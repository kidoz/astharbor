#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>
#include <llvm/ADT/SmallVector.h>
#include <unordered_set>

namespace astharbor {

/// Detects two or more unsequenced modifications of the same variable
/// in a single expression (CERT EXP30-C / C++ EXP50-CPP, CWE-758):
///
///     i++ + i++;         // UB: two modifications, no sequence point
///     a[i] = i++;        // UB: read+modify without sequence point
///     f(i++, i++);       // UB in C; unspecified in C++17+
///
/// The rule scans every full-expression for `++`/`--` operators
/// (prefix and postfix) and reports when the same `VarDecl` is
/// modified more than once.
class BugproneUnsequencedModificationRule : public Rule {
  public:
    std::string id() const override { return "bugprone/unsequenced-modification"; }
    std::string title() const override { return "Unsequenced modification"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Same variable modified more than once in a single expression "
               "without a sequence point — undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // Match any ++/-- on a local variable inside a binary operator,
        // call expression, or compound assignment — shapes where a
        // second modification of the same variable is most likely
        // unsequenced. We bind the enclosing full-expression rather
        // than the increment itself, then scan in run().
        Finder.addMatcher(
            binaryOperator(
                hasEitherOperand(ignoringParenImpCasts(
                    unaryOperator(
                        hasAnyOperatorName("++", "--"),
                        hasUnaryOperand(ignoringParenImpCasts(
                            declRefExpr(to(varDecl(hasLocalStorage())))))))))
                .bind("binop_with_mod"),
            this);
        Finder.addMatcher(
            callExpr(
                hasAnyArgument(ignoringParenImpCasts(
                    unaryOperator(
                        hasAnyOperatorName("++", "--"),
                        hasUnaryOperand(ignoringParenImpCasts(
                            declRefExpr(to(varDecl(hasLocalStorage())))))))))
                .bind("call_with_mod"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *BinOp =
            Result.Nodes.getNodeAs<clang::BinaryOperator>("binop_with_mod");
        const auto *CallNode =
            Result.Nodes.getNodeAs<clang::CallExpr>("call_with_mod");
        const clang::Expr *Root =
            BinOp != nullptr ? static_cast<const clang::Expr *>(BinOp)
                             : static_cast<const clang::Expr *>(CallNode);
        if (Root == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Root->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        // Collect all variables modified by ++ or -- under Root.
        llvm::SmallVector<std::pair<const clang::VarDecl *,
                                     clang::SourceLocation>, 4> mods;
        collectModifications(Root, mods);
        if (mods.size() < 2) {
            return;
        }

        // Check for duplicate VarDecls.
        std::unordered_set<const clang::VarDecl *> seen;
        for (const auto &[varDecl, loc] : mods) {
            if (!seen.insert(varDecl).second) {
                emitFinding(loc, *Result.SourceManager,
                            "'" + varDecl->getNameAsString() +
                                "' is modified more than once in a single "
                                "expression — undefined behavior");
                return; // one finding per expression
            }
        }
    }

  private:
    static void collectModifications(
        const clang::Stmt *stmt,
        llvm::SmallVectorImpl<std::pair<const clang::VarDecl *,
                                         clang::SourceLocation>> &mods) {
        if (stmt == nullptr) {
            return;
        }
        if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(stmt)) {
            if (unary->isIncrementDecrementOp()) {
                const auto *inner =
                    unary->getSubExpr()->IgnoreParenImpCasts();
                if (const auto *ref =
                        llvm::dyn_cast<clang::DeclRefExpr>(inner)) {
                    if (const auto *varDecl =
                            llvm::dyn_cast<clang::VarDecl>(ref->getDecl())) {
                        mods.push_back({varDecl, unary->getExprLoc()});
                    }
                }
            }
        }
        for (const clang::Stmt *child : stmt->children()) {
            collectModifications(child, mods);
        }
    }
};

} // namespace astharbor
