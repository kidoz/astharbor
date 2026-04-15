#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

/// Detects the classic EOF-narrowing bug (CERT FIO34-C / CWE-197):
///
///     char c;
///     while ((c = getchar()) != EOF) { ... }
///
/// `getchar()` / `getc()` / `fgetc()` return `int` so they can encode
/// the `EOF` sentinel `(int)-1`. Narrowing the return value to `char`
/// is lossy:
///
///   * On platforms where `char` is unsigned, the stored value can
///     never equal `EOF` when re-promoted to `int`, producing an
///     infinite loop or a silent data-byte misread.
///   * On platforms where `char` is signed, the valid input byte
///     `0xFF` narrows to `-1` and becomes indistinguishable from a
///     real EOF, ending the loop early.
///
/// The fix is to store the return value in an `int`.
///
/// Implementation: match the `ImplicitCastExpr` that narrows the
/// `int` return value to a char-typed destination. This hook catches
/// variable initialization, assignment, and function-argument
/// passing with a single matcher.
class BugproneCharEofComparisonRule : public Rule {
  public:
    std::string id() const override { return "bugprone/char-eof-comparison"; }
    std::string title() const override { return "getchar/getc/fgetc return narrowed to char"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Assigning the return value of getchar()/getc()/fgetc() to a char "
               "loses the EOF sentinel — store it in an int instead.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            implicitCastExpr(
                hasType(isAnyCharacter()),
                hasSourceExpression(ignoringParenImpCasts(
                    callExpr(callee(functionDecl(hasAnyName("getchar", "getc", "fgetc", "::getchar",
                                                            "::getc", "::fgetc", "std::getchar",
                                                            "std::getc", "std::fgetc"))))
                        .bind("io_call"))))
                .bind("narrowing_cast"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *IoCall = Result.Nodes.getNodeAs<clang::CallExpr>("io_call");
        if (IoCall == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(IoCall->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        const clang::FunctionDecl *callee = IoCall->getDirectCallee();
        const std::string calleeName = callee != nullptr ? callee->getNameAsString() : "getchar";
        emitFinding(IoCall->getExprLoc(), *Result.SourceManager,
                    "Return value of '" + calleeName +
                        "()' is narrowed to a char, which loses the EOF sentinel "
                        "— store it in an int instead");
    }
};

} // namespace astharbor
