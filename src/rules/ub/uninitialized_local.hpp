#pragma once
#include "astharbor/rule.hpp"
#include <clang/Analysis/CFG.h>
#include <deque>
#include <unordered_set>

namespace astharbor {

/// Detects reads of a local scalar variable before any write. Overlaps
/// somewhat with Clang's own `-Wuninitialized`, but runs inside the
/// ASTHarbor pipeline so findings flow through SARIF, fix command
/// plumbing, and the MCP server uniformly.
///
/// Uses a forward reachability analysis on the function's `clang::CFG`.
/// Starting from the CFG block that contains the `VarDecl`, we BFS over
/// successor blocks looking for the first read of the variable on any
/// path that has not been written yet. Paths that assign to the variable
/// (including address-of, which hands a write capability to callees) are
/// terminated before they can report a read. This is strictly better
/// than the previous source-order walker, which would miss reads in
/// branches that were reachable only via an unwritten path.
class UbUninitializedLocalRule : public Rule {
  public:
    std::string id() const override { return "ub/uninitialized-local"; }
    std::string title() const override { return "Uninitialized local scalar"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Read of a local scalar variable before any write — reading an indeterminate "
               "value is undefined behavior.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            varDecl(hasLocalStorage(), unless(hasInitializer(expr())),
                    hasType(qualType(anyOf(isInteger(), realFloatingPointType(),
                                            pointerType()))),
                    hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("uninit_var"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *UninitVar = Result.Nodes.getNodeAs<clang::VarDecl>("uninit_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (UninitVar == nullptr || Func == nullptr || !Func->hasBody() ||
            Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        // Skip static and thread-local locals — they are zero-initialized.
        if (UninitVar->isStaticLocal() ||
            UninitVar->getTLSKind() != clang::VarDecl::TLS_None) {
            return;
        }
        // Skip records and arrays — record types may have default constructors
        // and array initialization is handled elsewhere.
        clang::QualType type = UninitVar->getType();
        if (type->isRecordType() || type->isArrayType()) {
            return;
        }
        if (isInSystemHeader(UninitVar->getLocation(), *Result.SourceManager)) {
            return;
        }

        clang::CFG::BuildOptions options;
        auto cfg = clang::CFG::buildCFG(Func, Func->getBody(), Result.Context, options);
        if (!cfg) {
            return;
        }

        // Locate the CFG block and element index of the VarDecl statement.
        const clang::CFGBlock *declBlock = nullptr;
        size_t declIndex = 0;
        for (const clang::CFGBlock *block : *cfg) {
            if (block == nullptr) {
                continue;
            }
            for (size_t elementIndex = 0; elementIndex < block->size(); ++elementIndex) {
                auto cfgStmt = (*block)[elementIndex].getAs<clang::CFGStmt>();
                if (!cfgStmt) {
                    continue;
                }
                if (containsDeclOf(cfgStmt->getStmt(), UninitVar)) {
                    declBlock = block;
                    declIndex = elementIndex;
                    break;
                }
            }
            if (declBlock != nullptr) {
                break;
            }
        }
        if (declBlock == nullptr) {
            return;
        }

        // Forward BFS from the point just after the declaration. The first
        // read reached on a path that has not yet written to the variable
        // is the diagnostic. Writes (assignments or address-of) terminate
        // their path.
        std::unordered_set<const clang::CFGBlock *> visited;
        std::deque<std::pair<const clang::CFGBlock *, size_t>> work;
        work.emplace_back(declBlock, declIndex + 1);
        visited.insert(declBlock);

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
                // If the statement performs any write to the variable
                // (assignment, overloaded operator=, or address-of that
                // hands write capability to a callee), the path becomes
                // "fresh" and we stop exploring. Otherwise look for a
                // read — the first one reached on this path is the
                // diagnostic.
                if (containsWriteTo(statement, UninitVar)) {
                    stopThisPath = true;
                    break;
                }
                if (auto readLoc = findRead(statement, UninitVar)) {
                    reportLoc = *readLoc;
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
                    "Local '" + UninitVar->getNameAsString() +
                        "' is read before any write — reading an indeterminate value is "
                        "undefined behavior");
    }

  private:
    /// Return true if `stmt` is or contains a `DeclStmt` that declares
    /// `targetVar`. Used to find the CFG element owning the declaration.
    static bool containsDeclOf(const clang::Stmt *stmt,
                                const clang::VarDecl *targetVar) {
        if (stmt == nullptr) {
            return false;
        }
        if (const auto *declStmt = llvm::dyn_cast<clang::DeclStmt>(stmt)) {
            for (const clang::Decl *decl : declStmt->decls()) {
                if (decl == targetVar) {
                    return true;
                }
            }
        }
        for (const clang::Stmt *child : stmt->children()) {
            if (containsDeclOf(child, targetVar)) {
                return true;
            }
        }
        return false;
    }

    /// Return true if `stmt` recursively contains any write to `targetVar`:
    /// an assignment `x = ...`, an overloaded `operator=` whose LHS is
    /// `x`, or a unary `&x` (the address escapes, so a callee may init
    /// the variable).
    static bool containsWriteTo(const clang::Stmt *stmt,
                                 const clang::VarDecl *targetVar) {
        if (stmt == nullptr) {
            return false;
        }
        if (const auto *binary = llvm::dyn_cast<clang::BinaryOperator>(stmt);
            binary != nullptr && binary->isAssignmentOp() &&
            isDirectRefTo(binary->getLHS(), targetVar)) {
            return true;
        }
        if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(stmt);
            unary != nullptr && unary->getOpcode() == clang::UO_AddrOf &&
            isDirectRefTo(unary->getSubExpr(), targetVar)) {
            return true;
        }
        if (const auto *op = llvm::dyn_cast<clang::CXXOperatorCallExpr>(stmt);
            op != nullptr && op->getOperator() == clang::OO_Equal &&
            op->getNumArgs() == 2 && isDirectRefTo(op->getArg(0), targetVar)) {
            return true;
        }
        for (const clang::Stmt *child : stmt->children()) {
            if (containsWriteTo(child, targetVar)) {
                return true;
            }
        }
        return false;
    }

    /// Walk `stmt` looking for a read of `targetVar` — any `DeclRefExpr`
    /// to the variable that is not the LHS of an assignment to it.
    /// Address-of operands are not skipped here because the enclosing
    /// statement is already classified as a write via `containsWriteTo`
    /// and never reaches this function.
    static std::optional<clang::SourceLocation>
    findRead(const clang::Stmt *stmt, const clang::VarDecl *targetVar) {
        if (stmt == nullptr) {
            return std::nullopt;
        }
        // Skip LHS of an assignment to the target, but still check the RHS.
        if (const auto *binary = llvm::dyn_cast<clang::BinaryOperator>(stmt);
            binary != nullptr && binary->isAssignmentOp() &&
            isDirectRefTo(binary->getLHS(), targetVar)) {
            return findRead(binary->getRHS(), targetVar);
        }
        if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(stmt);
            ref != nullptr && ref->getDecl() == targetVar) {
            return ref->getBeginLoc();
        }
        for (const clang::Stmt *child : stmt->children()) {
            if (auto loc = findRead(child, targetVar)) {
                return loc;
            }
        }
        return std::nullopt;
    }

    static bool isDirectRefTo(const clang::Expr *expr,
                               const clang::VarDecl *targetVar) {
        if (expr == nullptr) {
            return false;
        }
        const auto *ref =
            llvm::dyn_cast<clang::DeclRefExpr>(expr->IgnoreParenImpCasts());
        return ref != nullptr && ref->getDecl() == targetVar;
    }
};

} // namespace astharbor
