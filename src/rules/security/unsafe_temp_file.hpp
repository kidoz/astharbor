#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityUnsafeTempFileRule : public Rule {
  public:
    std::string id() const override { return "security/unsafe-temp-file"; }
    std::string title() const override { return "Unsafe temporary file"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to tmpnam(), tempnam(), and mktemp() which create predictable or "
               "race-prone temporary file names.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("tmpnam", "tempnam", "mktemp", "::tmpnam",
                                                    "::tempnam", "::mktemp", "_mktemp"))))
                .bind("temp_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("temp_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "Use of insecure temporary file function — use mkstemp() or tmpfile() instead";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(Call->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(Call->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(Call->getExprLoc());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};
} // namespace astharbor
