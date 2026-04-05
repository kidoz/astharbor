#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>

namespace astharbor {

/// Detects functions that return a reference or address to a local
/// whose lifetime ends when the function returns — the returned
/// handle dangles the instant the caller tries to use it.
///
/// Three patterns are flagged:
///
///   T &f()        { int x;    return x;   }   // reference return of local
///   T *f()        { int x;    return &x;  }   // pointer return of &local
///   char *f()     { char p[10]; return p; }   // pointer return of array decay
///
/// Function parameters that are themselves references or pointers are
/// never flagged in the reference-return case — their referents live
/// in the caller's stack frame and are safe to pass through. Static
/// and thread-local locals are also excluded; their storage outlives
/// the function.
///
/// Overlaps with Clang's `-Wreturn-stack-address`; re-implemented here
/// so the finding flows through ASTHarbor's SARIF / MCP / LSP surface.
class UbDanglingReferenceRule : public Rule {
  public:
    std::string id() const override { return "ub/dangling-reference"; }
    std::string title() const override { return "Dangling reference to local"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Function returns a reference or pointer to a local whose storage ends "
               "when the function returns — undefined behavior on use.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        auto localVarRef = declRefExpr(
            to(varDecl(hasLocalStorage()).bind("local_var")));

        // Reference return: `T &f() { ... return local; }`
        Finder.addMatcher(
            returnStmt(
                hasReturnValue(ignoringParenImpCasts(localVarRef)),
                hasAncestor(functionDecl(returns(referenceType()), isDefinition())
                                .bind("enclosing_func")))
                .bind("return_ref"),
            this);
        // Pointer return, either via address-of a local or via array-to-
        // pointer decay of a local array. Both shapes end up handing
        // the caller a pointer into storage that ends at return.
        Finder.addMatcher(
            returnStmt(
                hasReturnValue(ignoringParenImpCasts(anyOf(
                    unaryOperator(hasOperatorName("&"),
                                   hasUnaryOperand(ignoringParenImpCasts(localVarRef))),
                    declRefExpr(
                        to(varDecl(hasLocalStorage(), hasType(arrayType()))
                               .bind("local_var")))))),
                hasAncestor(functionDecl(returns(pointerType()), isDefinition())
                                .bind("enclosing_func")))
                .bind("return_addr"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *LocalVar = Result.Nodes.getNodeAs<clang::VarDecl>("local_var");
        const auto *ReturnRef = Result.Nodes.getNodeAs<clang::ReturnStmt>("return_ref");
        const auto *ReturnAddr =
            Result.Nodes.getNodeAs<clang::ReturnStmt>("return_addr");
        const clang::ReturnStmt *ReturnNode =
            ReturnRef != nullptr ? ReturnRef : ReturnAddr;
        if (LocalVar == nullptr || ReturnNode == nullptr ||
            Result.SourceManager == nullptr) {
            return;
        }
        // Static and thread-local storage outlives the function body.
        if (LocalVar->isStaticLocal() ||
            LocalVar->getTLSKind() != clang::VarDecl::TLS_None) {
            return;
        }
        // Reference return: a parameter that is itself a reference or
        // pointer refers to caller-owned storage. Returning it is safe.
        // (The pointer-return pattern takes the address of the
        // parameter slot itself, which IS local — flag it unchanged.)
        if (ReturnRef != nullptr) {
            if (const auto *parm = llvm::dyn_cast<clang::ParmVarDecl>(LocalVar)) {
                clang::QualType type = parm->getType();
                if (type->isReferenceType() || type->isPointerType()) {
                    return;
                }
            }
        }
        if (isInSystemHeader(ReturnNode->getBeginLoc(), *Result.SourceManager)) {
            return;
        }

        const char *kind = ReturnRef != nullptr ? "reference" : "pointer";
        emitFinding(ReturnNode->getBeginLoc(), *Result.SourceManager,
                    std::string("Returning ") + kind + " to local '" +
                        LocalVar->getNameAsString() +
                        "' — storage ends when the function returns; the caller "
                        "receives a dangling " + kind);
    }
};

} // namespace astharbor
