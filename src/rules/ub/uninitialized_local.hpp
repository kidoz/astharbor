#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"
#include <optional>

namespace astharbor {

/// Detects reads of a local scalar variable before any write. Overlaps
/// somewhat with Clang's own `-Wuninitialized`, but runs inside the
/// ASTHarbor pipeline so findings flow through SARIF, fix command
/// plumbing, and the MCP server uniformly.
///
/// Implemented as a CFG forward reachability query: BFS forward from
/// the variable's declaration, treating assignments and address-of
/// operations as path terminators (the latter because a callee may
/// initialize through the pointer) and the first surviving read as the
/// diagnostic.
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
        // Static and thread-local locals are zero-initialized; record
        // types may have default constructors; arrays are initialized
        // elsewhere. None of these are in scope for this rule.
        if (UninitVar->isStaticLocal() ||
            UninitVar->getTLSKind() != clang::VarDecl::TLS_None) {
            return;
        }
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

        auto start = cfg::locateDecl(*cfg, UninitVar);
        if (!start) {
            return;
        }

        auto reportLoc = cfg::forwardReachable(
            start->first, start->second,
            [&](const clang::Stmt *stmt) {
                return containsWriteTo(stmt, UninitVar);
            },
            [&](const clang::Stmt *stmt) {
                return findRead(stmt, UninitVar).value_or(clang::SourceLocation{});
            });

        if (!reportLoc || reportLoc->isInvalid()) {
            return;
        }
        emitFinding(*reportLoc, *Result.SourceManager,
                    "Local '" + UninitVar->getNameAsString() +
                        "' is read before any write — reading an indeterminate value is "
                        "undefined behavior");
    }

  private:
    /// Return true if `stmt` recursively contains a write to `targetVar`:
    /// an assignment, an overloaded `operator=`, or a `&targetVar`. The
    /// address-of case is treated as a write because once a callee holds
    /// the pointer, we can no longer reason locally about whether the
    /// variable has been initialized.
    static bool containsWriteTo(const clang::Stmt *stmt,
                                 const clang::VarDecl *targetVar) {
        if (stmt == nullptr) {
            return false;
        }
        if (cfg::isAssignmentTo(stmt, targetVar)) {
            return true;
        }
        if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(stmt);
            unary != nullptr && unary->getOpcode() == clang::UO_AddrOf &&
            cfg::isDirectRefTo(unary->getSubExpr(), targetVar)) {
            return true;
        }
        for (const clang::Stmt *child : stmt->children()) {
            if (containsWriteTo(child, targetVar)) {
                return true;
            }
        }
        return false;
    }

    /// Walk `stmt` looking for a `DeclRefExpr` to `targetVar` that is not
    /// the LHS of an assignment to it. The enclosing BFS has already
    /// filtered out statements containing any write to the variable, so
    /// a surviving DeclRefExpr on this path is a read before any write.
    static std::optional<clang::SourceLocation>
    findRead(const clang::Stmt *stmt, const clang::VarDecl *targetVar) {
        if (stmt == nullptr) {
            return std::nullopt;
        }
        if (const auto *binary = llvm::dyn_cast<clang::BinaryOperator>(stmt);
            binary != nullptr && binary->isAssignmentOp() &&
            cfg::isDirectRefTo(binary->getLHS(), targetVar)) {
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
};

} // namespace astharbor
