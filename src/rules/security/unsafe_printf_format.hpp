#pragma once
#include "astharbor/rule.hpp"
#include <llvm/Support/Casting.h>

namespace astharbor {
class SecurityUnsafePrintfFormatRule : public Rule {
  public:
    std::string id() const override { return "security/unsafe-printf-format"; }
    std::string title() const override { return "Unsafe printf format"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects printf-family calls where the format string is not a string literal, "
               "risking format string injection.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName(
                         "printf", "fprintf", "sprintf", "snprintf", "dprintf",
                         "wprintf", "fwprintf", "swprintf",
                         "::printf", "::fprintf", "::sprintf", "::snprintf",
                         "std::printf", "std::fprintf", "std::sprintf", "std::snprintf"))))
                .bind("printf_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("printf_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        const auto *Callee = Call->getDirectCallee();
        if (Callee == nullptr) {
            return;
        }

        unsigned FormatArgIndex = getFormatArgIndex(Callee->getName());
        if (FormatArgIndex >= Call->getNumArgs()) {
            return;
        }

        const auto *FormatArg = Call->getArg(FormatArgIndex)->IgnoreParenImpCasts();
        if (llvm::isa<clang::StringLiteral>(FormatArg)) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message = "Format string is not a string literal — this may allow format string injection (CWE-134)";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(Call->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(Call->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(Call->getExprLoc());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }

  private:
    static unsigned getFormatArgIndex(llvm::StringRef FunctionName) {
        if (FunctionName == "printf" || FunctionName == "wprintf") {
            return 0;
        }
        if (FunctionName == "snprintf" || FunctionName == "swprintf") {
            return 2;
        }
        // fprintf, sprintf, dprintf, fwprintf: format at arg 1
        return 1;
    }
};
} // namespace astharbor
