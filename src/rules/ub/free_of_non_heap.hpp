#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

/// Detects `free()` called on memory that was not obtained from an
/// allocator — undefined behavior per CERT MEM34-C / CWE-590:
///
///     int x;           free(&x);       // stack variable
///     static int s;    free(&s);       // static / global
///     int arr[10];     free(arr);      // decayed local array
///     static int sa[]; free(sa);       // decayed static array
///                      free("hello");  // string literal
///
/// Matches the argument of `free` / `std::free` against five shapes
/// that can never come from a heap allocator: address-of a
/// local/static variable, decayed local/static array, or a string
/// literal. All five are pure AST patterns — no CFG needed.
class UbFreeOfNonHeapRule : public Rule {
  public:
    std::string id() const override { return "ub/free-of-non-heap"; }
    std::string title() const override { return "free() on non-heap memory"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "free() called on a stack variable, static/global, or string literal "
               "— the pointer was never returned by malloc and freeing it is "
               "undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        auto freeFunc =
            callee(functionDecl(hasAnyName("free", "::free", "std::free", "::std::free")));
        auto anyStorageVar = varDecl(anyOf(hasLocalStorage(), hasGlobalStorage()));
        auto addressOfVar = unaryOperator(hasOperatorName("&"),
                                          hasUnaryOperand(ignoringParenImpCasts(
                                              declRefExpr(to(anyStorageVar.bind("target_var"))))));
        auto arrayDecayVar = declRefExpr(
            to(varDecl(anyOf(hasLocalStorage(), hasGlobalStorage()), hasType(arrayType()))
                   .bind("target_var")));

        // Shape 1+2: free(&local) / free(&static)
        Finder.addMatcher(callExpr(freeFunc, hasArgument(0, ignoringParenImpCasts(addressOfVar)))
                              .bind("free_call"),
                          this);
        // Shape 3+4: free(local_array) / free(static_array) — array decay
        Finder.addMatcher(callExpr(freeFunc, hasArgument(0, ignoringParenImpCasts(arrayDecayVar)))
                              .bind("free_call"),
                          this);
        // Shape 5: free("literal") / free((void*)"literal") — the user
        // typically writes a C-style cast to void* around the literal,
        // so `hasDescendant` looks through any cast chain to find the
        // underlying string literal.
        Finder.addMatcher(
            callExpr(freeFunc, hasArgument(0, hasDescendant(stringLiteral().bind("string_lit"))))
                .bind("free_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *FreeCall = Result.Nodes.getNodeAs<clang::CallExpr>("free_call");
        if (FreeCall == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(FreeCall->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        const auto *TargetVar = Result.Nodes.getNodeAs<clang::VarDecl>("target_var");
        const auto *StringLit = Result.Nodes.getNodeAs<clang::StringLiteral>("string_lit");

        std::string description;
        if (TargetVar != nullptr) {
            const char *storage = TargetVar->hasLocalStorage() ? "stack" : "global/static";
            description = "free() called on " + std::string(storage) + " variable '" +
                          TargetVar->getNameAsString() +
                          "' — not heap-allocated, undefined behavior";
        } else if (StringLit != nullptr) {
            description = "free() called on a string literal — not "
                          "heap-allocated, undefined behavior";
        } else {
            description = "free() called on non-heap memory — undefined behavior";
        }
        emitFinding(FreeCall->getExprLoc(), *Result.SourceManager, description);
    }
};

} // namespace astharbor
