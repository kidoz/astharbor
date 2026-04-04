#pragma once
#include "astharbor/rule.hpp"
#include <llvm/Support/Casting.h>

namespace astharbor {
class SecurityNoScanfWithoutWidthRule : public Rule {
  public:
    std::string id() const override { return "security/no-scanf-without-width"; }
    std::string title() const override { return "No scanf without width"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects scanf-family calls with bare %s (no field width), which can overflow the "
               "destination buffer.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName(
                         "scanf", "fscanf", "sscanf",
                         "::scanf", "::fscanf", "::sscanf",
                         "std::scanf", "std::fscanf", "std::sscanf"))))
                .bind("scanf_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("scanf_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        const auto *Callee = Call->getDirectCallee();
        if (Callee == nullptr) {
            return;
        }

        unsigned FormatArgIndex = 0;
        llvm::StringRef FunctionName = Callee->getName();
        if (FunctionName == "fscanf" || FunctionName == "sscanf") {
            FormatArgIndex = 1;
        }

        if (FormatArgIndex >= Call->getNumArgs()) {
            return;
        }

        const auto *FormatArg = Call->getArg(FormatArgIndex)->IgnoreParenImpCasts();
        const auto *FormatLiteral = llvm::dyn_cast<clang::StringLiteral>(FormatArg);
        if (FormatLiteral == nullptr) {
            return;
        }

        if (!hasBareScanfStringSpecifier(FormatLiteral->getString())) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "scanf-family call uses %s without a field width — this can overflow the destination "
            "buffer (CWE-120). Use a width specifier (e.g. %32s)";
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
    static bool hasBareScanfStringSpecifier(llvm::StringRef FormatStr) {
        for (size_t position = 0; position < FormatStr.size(); ++position) {
            if (FormatStr[position] != '%') {
                continue;
            }
            ++position;
            if (position >= FormatStr.size()) {
                break;
            }
            if (FormatStr[position] == '%') {
                continue;
            }

            // Skip flags
            while (position < FormatStr.size() &&
                   (FormatStr[position] == '-' || FormatStr[position] == '+' ||
                    FormatStr[position] == ' ' || FormatStr[position] == '#' ||
                    FormatStr[position] == '0')) {
                ++position;
            }

            // Check for width digits
            bool hasWidth = false;
            while (position < FormatStr.size() && FormatStr[position] >= '0' &&
                   FormatStr[position] <= '9') {
                hasWidth = true;
                ++position;
            }

            // Skip 'l' length modifier for %ls
            if (position < FormatStr.size() && FormatStr[position] == 'l') {
                ++position;
            }

            // Check for string specifiers
            if (position < FormatStr.size() &&
                (FormatStr[position] == 's' || FormatStr[position] == 'S' ||
                 FormatStr[position] == '[')) {
                if (!hasWidth) {
                    return true;
                }
            }
        }
        return false;
    }
};
} // namespace astharbor
