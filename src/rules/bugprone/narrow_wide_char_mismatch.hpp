#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

/// Detects narrow-string functions called with wide-char arguments and
/// vice versa (CERT STR38-C / CWE-704). The mismatch is typically
/// hidden behind an explicit cast that the compiler accepts silently:
///
///     wchar_t *ws = L"hello";
///     strlen((const char*)ws);     // wrong — strlen walks byte-by-byte
///
/// The rule strips all casts from each argument and checks whether
/// the source type's pointee character width matches the function's
/// expected width.
class BugproneNarrowWideCharMismatchRule : public Rule {
  public:
    std::string id() const override { return "bugprone/narrow-wide-char-mismatch"; }
    std::string title() const override { return "Narrow/wide character function mismatch"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "A narrow-string function is called with a wide-char argument or "
               "vice versa — the buffer is silently reinterpreted.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName(
                         "strlen", "strcmp", "strncmp", "strchr", "strrchr", "strstr", "strtok",
                         "strcpy", "strncpy", "strcat", "strncat", "memchr", "::strlen", "::strcmp",
                         "::strncmp", "::strchr", "::strrchr", "::strstr", "::strtok", "::strcpy",
                         "::strncpy", "::strcat", "::strncat", "::memchr"))))
                .bind("narrow_call"),
            this);
        Finder.addMatcher(
            callExpr(callee(functionDecl(
                         hasAnyName("wcslen", "wcscmp", "wcsncmp", "wcschr", "wcsrchr", "wcsstr",
                                    "wcstok", "wcscpy", "wcsncpy", "wcscat", "wcsncat", "::wcslen",
                                    "::wcscmp", "::wcsncmp", "::wcschr", "::wcsrchr", "::wcsstr",
                                    "::wcstok", "::wcscpy", "::wcsncpy", "::wcscat", "::wcsncat"))))
                .bind("wide_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *NarrowCall = Result.Nodes.getNodeAs<clang::CallExpr>("narrow_call");
        const auto *WideCall = Result.Nodes.getNodeAs<clang::CallExpr>("wide_call");
        const clang::CallExpr *Call = NarrowCall != nullptr ? NarrowCall : WideCall;
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        const bool expectsNarrow = (NarrowCall != nullptr);
        for (unsigned index = 0; index < Call->getNumArgs(); ++index) {
            // Strip ALL casts (implicit + explicit) to get the source type.
            const clang::Expr *stripped = Call->getArg(index)->IgnoreCasts();
            const clang::QualType sourceType = stripped->getType();
            if (sourceType.isNull()) {
                continue;
            }
            const clang::QualType pointee = sourceType->getPointeeType();
            if (pointee.isNull()) {
                continue;
            }
            const bool sourceIsWide = pointee->isWideCharType();
            const bool sourceIsNarrow = pointee->isCharType();
            if ((expectsNarrow && sourceIsWide) || (!expectsNarrow && sourceIsNarrow)) {
                const clang::FunctionDecl *callee = Call->getDirectCallee();
                const std::string calleeName = callee != nullptr ? callee->getNameAsString() : "?";
                const char *expected = expectsNarrow ? "narrow" : "wide";
                const char *actual = expectsNarrow ? "wide" : "narrow";
                emitFinding(Call->getArg(index)->getBeginLoc(), *Result.SourceManager,
                            calleeName + "() expects " + expected +
                                " characters but argument source is " + actual);
                return;
            }
        }
    }
};

} // namespace astharbor
