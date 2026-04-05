#pragma once
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/Analysis/CFG.h>
#include <clang/Basic/SourceLocation.h>
#include <deque>
#include <functional>
#include <optional>
#include <unordered_set>
#include <utility>

namespace astharbor::cfg {

/// Shared scaffolding for CFG-based forward reachability rules.
///
/// Several Tier 2 rules (ub/use-after-move, ub/double-free-local,
/// ub/uninitialized-local) need the same three things:
///   1. locate a specific starting Stmt inside a freshly-built CFG,
///   2. walk forward from there in BFS order, scanning each reachable
///      CFG element,
///   3. let the rule classify each statement as terminating the path
///      (a reassignment / write) or as the diagnostic (a use / read /
///      second-delete) — while the BFS driver handles visited-set
///      bookkeeping, loop cycles, and successor enumeration.
///
/// Instead of open-coding the walker in every rule, rules supply two
/// predicates to `forwardReachable`: a `StopsPath` check and a
/// `FindsReport` check. The helper owns the loop.

/// Return true if `haystack` is or contains `needle` as a sub-expression.
inline bool containsStmt(const clang::Stmt *haystack, const clang::Stmt *needle) {
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

/// Return true if `expr`, after stripping parens and implicit casts, is a
/// direct `DeclRefExpr` to `targetVar`.
inline bool isDirectRefTo(const clang::Expr *expr,
                           const clang::VarDecl *targetVar) {
    if (expr == nullptr || targetVar == nullptr) {
        return false;
    }
    const auto *ref =
        llvm::dyn_cast<clang::DeclRefExpr>(expr->IgnoreParenImpCasts());
    return ref != nullptr && ref->getDecl() == targetVar;
}

/// Return true if `stmt` is itself a top-level assignment whose LHS is
/// `targetVar`. Matches both builtin assignments (`BinaryOperator`) and
/// overloaded `operator=` calls (`CXXOperatorCallExpr`). The check is
/// intentionally shallow: CFG elements land at statement granularity, so
/// looking at the top-level is enough and a recursive walk would report
/// nested assignments the CFG has already split out into their own
/// elements.
inline bool isAssignmentTo(const clang::Stmt *stmt,
                            const clang::VarDecl *targetVar) {
    if (stmt == nullptr) {
        return false;
    }
    if (const auto *binary = llvm::dyn_cast<clang::BinaryOperator>(stmt)) {
        return binary->isAssignmentOp() &&
               isDirectRefTo(binary->getLHS(), targetVar);
    }
    if (const auto *op = llvm::dyn_cast<clang::CXXOperatorCallExpr>(stmt)) {
        return op->getOperator() == clang::OO_Equal && op->getNumArgs() == 2 &&
               isDirectRefTo(op->getArg(0), targetVar);
    }
    return false;
}

/// Locate the (block, element-index) pair whose CFG statement owns
/// `needle` (or a sub-expression containing it). Returns nullopt if the
/// statement does not appear in any block — which can happen for
/// synthesized nodes — so callers can short-circuit safely.
inline std::optional<std::pair<const clang::CFGBlock *, size_t>>
locateStmt(const clang::CFG &cfg, const clang::Stmt *needle) {
    for (const clang::CFGBlock *block : cfg) {
        if (block == nullptr) {
            continue;
        }
        for (size_t elementIndex = 0; elementIndex < block->size(); ++elementIndex) {
            auto cfgStmt = (*block)[elementIndex].getAs<clang::CFGStmt>();
            if (!cfgStmt) {
                continue;
            }
            if (containsStmt(cfgStmt->getStmt(), needle)) {
                return std::make_pair(block, elementIndex);
            }
        }
    }
    return std::nullopt;
}

/// Locate the (block, element-index) pair whose CFG statement declares
/// `targetVar`. The starting block for "reads before writes" dataflow.
inline std::optional<std::pair<const clang::CFGBlock *, size_t>>
locateDecl(const clang::CFG &cfg, const clang::VarDecl *targetVar) {
    if (targetVar == nullptr) {
        return std::nullopt;
    }
    auto containsDecl = [&](const clang::Stmt *stmt) {
        std::function<bool(const clang::Stmt *)> recurse =
            [&](const clang::Stmt *node) {
                if (node == nullptr) {
                    return false;
                }
                if (const auto *declStmt = llvm::dyn_cast<clang::DeclStmt>(node)) {
                    for (const clang::Decl *decl : declStmt->decls()) {
                        if (decl == targetVar) {
                            return true;
                        }
                    }
                }
                for (const clang::Stmt *child : node->children()) {
                    if (recurse(child)) {
                        return true;
                    }
                }
                return false;
            };
        return recurse(stmt);
    };
    for (const clang::CFGBlock *block : cfg) {
        if (block == nullptr) {
            continue;
        }
        for (size_t elementIndex = 0; elementIndex < block->size(); ++elementIndex) {
            auto cfgStmt = (*block)[elementIndex].getAs<clang::CFGStmt>();
            if (!cfgStmt) {
                continue;
            }
            if (containsDecl(cfgStmt->getStmt())) {
                return std::make_pair(block, elementIndex);
            }
        }
    }
    return std::nullopt;
}

/// BFS driver for "is there a reachable statement matching some predicate
/// before a reassignment/write happens?" dataflow.
///
/// Starting from `(startBlock, startIndex + 1)` — i.e. the element right
/// after the triggering statement — visit reachable CFG elements in BFS
/// order. For each `clang::Stmt` in a reached element, in order:
///   * if `stopsPath(stmt)` returns true, this path is considered "fresh"
///     from here; stop scanning and do not enqueue successors via the
///     scanning loop (visited bookkeeping still prevents revisits),
///   * otherwise call `findsReport(stmt)`; if it returns a valid source
///     location, that is the diagnostic and the walk terminates.
///
/// Returns the first reporting location, or nullopt if no path reaches
/// such a statement. `stopsPath` is checked before `findsReport` so a
/// statement that is both a write and a read (e.g. `x = x + 1`) is
/// treated as a write and does not report from itself — the rules rely
/// on the CFG decomposing such compound expressions into separate
/// elements when that distinction matters.
template <typename StopsPath, typename FindsReport>
std::optional<clang::SourceLocation>
forwardReachable(const clang::CFGBlock *startBlock, size_t startIndex,
                 StopsPath stopsPath, FindsReport findsReport) {
    if (startBlock == nullptr) {
        return std::nullopt;
    }
    std::unordered_set<const clang::CFGBlock *> visited;
    std::deque<std::pair<const clang::CFGBlock *, size_t>> work;
    work.emplace_back(startBlock, startIndex + 1);
    visited.insert(startBlock);

    while (!work.empty()) {
        auto [block, scanFrom] = work.front();
        work.pop_front();

        bool stopThisPath = false;
        for (size_t elementIndex = scanFrom;
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
            if (stopsPath(statement)) {
                stopThisPath = true;
                break;
            }
            if (auto reportLoc = findsReport(statement); reportLoc.isValid()) {
                return reportLoc;
            }
        }
        if (stopThisPath) {
            continue;
        }
        for (auto successor : block->succs()) {
            const clang::CFGBlock *nextBlock = successor.getReachableBlock();
            if (nextBlock == nullptr || !visited.insert(nextBlock).second) {
                continue;
            }
            work.emplace_back(nextBlock, 0);
        }
    }
    return std::nullopt;
}

} // namespace astharbor::cfg
