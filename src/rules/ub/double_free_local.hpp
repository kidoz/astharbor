#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/ExprCXX.h>
#include <clang/Analysis/CFG.h>
#include <deque>
#include <unordered_set>

namespace astharbor {

/// Detects two `delete` calls on the same local pointer variable within a
/// function body, without an intervening reassignment. Per [expr.delete]/4
/// the pointer operand must have come from exactly one prior new-expression,
/// so reusing the same pointer for a second delete is undefined behavior
/// (and typically crashes).
///
/// Uses a forward reachability analysis on the function's `clang::CFG`.
/// Starting from the CFG block that contains the first `delete p` call,
/// we BFS over successor blocks and look for a second `delete p` on any
/// reachable path. Paths that reassign `p` are terminated (the pointer is
/// fresh again). Paths that never reach a second delete (e.g., early
/// return, throw) are correctly excluded — a significant improvement over
/// the previous source-order walker which reported branches that can
/// never execute together.
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

        // Build the CFG for the enclosing function body.
        clang::CFG::BuildOptions options;
        auto cfg = clang::CFG::buildCFG(Func, Func->getBody(), Result.Context, options);
        if (!cfg) {
            return;
        }

        // Locate the CFG block and element index of the first delete.
        const clang::CFGBlock *deleteBlock = nullptr;
        size_t deleteIndex = 0;
        for (const clang::CFGBlock *block : *cfg) {
            if (block == nullptr) {
                continue;
            }
            for (size_t elementIndex = 0; elementIndex < block->size(); ++elementIndex) {
                auto cfgStmt = (*block)[elementIndex].getAs<clang::CFGStmt>();
                if (!cfgStmt) {
                    continue;
                }
                if (containsStmt(cfgStmt->getStmt(), FirstDelete)) {
                    deleteBlock = block;
                    deleteIndex = elementIndex;
                    break;
                }
            }
            if (deleteBlock != nullptr) {
                break;
            }
        }
        if (deleteBlock == nullptr) {
            return;
        }

        // Forward BFS from the point just after the first delete. For each
        // reached block we scan its statements in order and stop on
        // reassignment. A matching second delete on any reachable path is
        // a diagnostic.
        std::unordered_set<const clang::CFGBlock *> visited;
        std::deque<std::pair<const clang::CFGBlock *, size_t>> work;
        work.emplace_back(deleteBlock, deleteIndex + 1);
        visited.insert(deleteBlock);

        clang::SourceLocation reportLoc;

        while (!work.empty() && reportLoc.isInvalid()) {
            auto [block, startIndex] = work.front();
            work.pop_front();

            bool stopThisPath = false;
            for (size_t elementIndex = startIndex;
                 elementIndex < block->size() && !stopThisPath;
                 ++elementIndex) {
                auto cfgStmt = (*block)[elementIndex].getAs<clang::CFGStmt>();
                if (!cfgStmt) {
                    continue;
                }
                const clang::Stmt *statement = cfgStmt->getStmt();
                if (statement == nullptr) {
                    continue;
                }
                if (isReassignmentOf(statement, DeletedVar)) {
                    stopThisPath = true;
                    break;
                }
                if (auto secondLoc =
                        findSecondDeleteLocation(statement, DeletedVar, FirstDelete)) {
                    reportLoc = *secondLoc;
                    break;
                }
            }

            if (reportLoc.isValid()) {
                break;
            }
            if (stopThisPath) {
                continue;
            }

            for (auto successor : block->succs()) {
                const clang::CFGBlock *nextBlock = successor.getReachableBlock();
                if (nextBlock == nullptr || visited.count(nextBlock) > 0) {
                    continue;
                }
                visited.insert(nextBlock);
                work.emplace_back(nextBlock, 0);
            }
        }

        if (reportLoc.isInvalid()) {
            return;
        }

        emitFinding(reportLoc, *Result.SourceManager,
                    "Pointer '" + DeletedVar->getNameAsString() +
                        "' is deleted twice within this function without an intervening "
                        "reassignment — undefined behavior");
    }

  private:
    /// Return true if `haystack` is or contains `needle` as a sub-expression.
    static bool containsStmt(const clang::Stmt *haystack, const clang::Stmt *needle) {
        if (haystack == nullptr || needle == nullptr) {
            return false;
        }
        if (haystack == needle) {
            return true;
        }
        for (const clang::Stmt *child : haystack->children()) {
            if (containsStmt(child, needle)) {
                return true;
            }
        }
        return false;
    }

    /// Return true if `stmt` is a reassignment to `targetVar` — either a
    /// plain `BinaryOperator` assignment or an overloaded `operator=` call.
    static bool isReassignmentOf(const clang::Stmt *stmt,
                                  const clang::VarDecl *targetVar) {
        if (const auto *binary = llvm::dyn_cast<clang::BinaryOperator>(stmt)) {
            if (binary->isAssignmentOp()) {
                const auto *lhs = binary->getLHS()->IgnoreParenImpCasts();
                if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(lhs)) {
                    return ref->getDecl() == targetVar;
                }
            }
            return false;
        }
        if (const auto *op = llvm::dyn_cast<clang::CXXOperatorCallExpr>(stmt)) {
            if (op->getOperator() == clang::OO_Equal && op->getNumArgs() == 2) {
                const auto *lhs = op->getArg(0)->IgnoreParenImpCasts();
                if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(lhs)) {
                    return ref->getDecl() == targetVar;
                }
            }
        }
        return false;
    }

    /// Recursively look for a `CXXDeleteExpr` operating on `targetVar` that
    /// is not `excludedDelete` (the first delete itself). Returns the
    /// location of the delete expression if found.
    static std::optional<clang::SourceLocation>
    findSecondDeleteLocation(const clang::Stmt *stmt, const clang::VarDecl *targetVar,
                             const clang::CXXDeleteExpr *excludedDelete) {
        if (stmt == nullptr || stmt == excludedDelete) {
            return std::nullopt;
        }
        if (const auto *deleteExpr = llvm::dyn_cast<clang::CXXDeleteExpr>(stmt)) {
            const auto *arg = deleteExpr->getArgument()->IgnoreParenImpCasts();
            if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(arg);
                ref != nullptr && ref->getDecl() == targetVar) {
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
