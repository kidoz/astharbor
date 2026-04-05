#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/ExprCXX.h>
#include <clang/Analysis/CFG.h>
#include <deque>
#include <unordered_set>

namespace astharbor {

/// Detects uses of a local variable after `std::move(x)` has been called
/// on it, without an intervening reassignment. Per [lib.types.movedfrom]
/// the moved-from object is in a valid-but-unspecified state; methods
/// other than destruction or reassignment are generally a defect. For
/// types like `std::unique_ptr` the subsequent use is actual undefined
/// behavior on dereference.
///
/// Uses a forward reachability analysis on the function's `clang::CFG`.
/// Starting from the CFG block that contains the `std::move(x)` call,
/// we BFS over successor blocks and check each reached statement for a
/// use of `x`. Paths that reassign `x` are terminated (the variable is
/// fresh again). Paths that never reach the use (e.g., early return,
/// terminator statements) are correctly excluded — a significant
/// improvement over the previous source-order walker.
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

        // Build the CFG for the enclosing function body. Disable pruning of
        // "trivially false" edges so we don't accidentally drop the exact
        // branches we want to reason about.
        clang::CFG::BuildOptions options;
        auto cfg = clang::CFG::buildCFG(Func, Func->getBody(), Result.Context, options);
        if (!cfg) {
            return;
        }

        // Locate the CFG block and element index of the move call.
        const clang::CFGBlock *moveBlock = nullptr;
        size_t moveIndex = 0;
        for (const clang::CFGBlock *block : *cfg) {
            if (block == nullptr) {
                continue;
            }
            for (size_t elementIndex = 0; elementIndex < block->size(); ++elementIndex) {
                auto cfgStmt = (*block)[elementIndex].getAs<clang::CFGStmt>();
                if (!cfgStmt) {
                    continue;
                }
                if (containsStmt(cfgStmt->getStmt(), MoveCall)) {
                    moveBlock = block;
                    moveIndex = elementIndex;
                    break;
                }
            }
            if (moveBlock != nullptr) {
                break;
            }
        }
        if (moveBlock == nullptr) {
            return;
        }

        // Forward BFS from the point just after the move. For each reached
        // block we scan its statements in order and stop on reassignment.
        // Blocks already visited are skipped to handle loops.
        std::unordered_set<const clang::CFGBlock *> visited;
        std::deque<std::pair<const clang::CFGBlock *, size_t>> work;

        // The remainder of moveBlock past moveIndex is the first segment.
        work.emplace_back(moveBlock, moveIndex + 1);
        visited.insert(moveBlock);

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
                // Reassignment? Then this path is "fresh" from here on —
                // stop exploring but don't report.
                if (isReassignmentOf(statement, MovedVar)) {
                    stopThisPath = true;
                    break;
                }
                // Does this statement use the moved variable?
                if (auto useLoc = findUseLocation(statement, MovedVar, MoveCall)) {
                    reportLoc = *useLoc;
                    break;
                }
            }

            if (reportLoc.isValid()) {
                break;
            }
            if (stopThisPath) {
                continue;
            }

            // Enqueue successor blocks (skipping null successors and ones
            // already visited). Terminator-only successors (exit block) are
            // harmless since they have no statements to scan.
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
                    "Use of '" + MovedVar->getNameAsString() +
                        "' after std::move — the value is in a valid-but-unspecified "
                        "state; reassign before reusing or drop the std::move");
    }

  private:
    /// Return true if `haystack` is or contains `needle` as a sub-expression.
    /// Used to find the CFG statement that owns the std::move call.
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
        // Visit the stmt looking for an assignment whose LHS is targetVar.
        // Single-level check is enough because the CFG puts each assignment
        // at its own element.
        if (const auto *binary = llvm::dyn_cast<clang::BinaryOperator>(stmt)) {
            if (binary->isAssignmentOp()) {
                const auto *lhs =
                    binary->getLHS()->IgnoreParenImpCasts();
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

    /// Find the first DeclRefExpr to `targetVar` in `stmt` that is not part
    /// of `excludedCall` (the move call itself). Returns the location of
    /// the reference if found.
    static std::optional<clang::SourceLocation>
    findUseLocation(const clang::Stmt *stmt, const clang::VarDecl *targetVar,
                    const clang::CallExpr *excludedCall) {
        if (stmt == nullptr || stmt == excludedCall) {
            return std::nullopt;
        }
        if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(stmt)) {
            if (ref->getDecl() == targetVar) {
                return ref->getBeginLoc();
            }
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
