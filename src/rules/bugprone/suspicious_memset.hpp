#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class BugproneSuspiciousMemsetRule : public Rule {
  public:
    std::string id() const override { return "bugprone/suspicious-memset"; }
    std::string title() const override { return "Suspicious memset"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override { return "Detects memset calls where the size argument is sizeof(pointer)."; }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        
        Finder.addMatcher(
            callExpr(
                callee(functionDecl(hasName("memset"))),
                hasArgument(2, ignoringParenImpCasts(
                    unaryExprOrTypeTraitExpr(
                        ofKind(clang::UETT_SizeOf),
                        hasArgumentOfType(pointerType())
                    ).bind("sizeof_ptr")
                ))
            ).bind("memset_call"),
            this
        );
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        if (const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("memset_call")) {
            if (Result.SourceManager == nullptr) {
                return;
            }

            if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
                return;
            }

            Finding finding;
            finding.ruleId = id();
            finding.message = "Suspicious memset: the size argument is sizeof(pointer) rather than the size of the pointed-to data";
            finding.severity = defaultSeverity();
            finding.category = category();

            auto &sourceManager = *Result.SourceManager;
            finding.file = sourceManager.getFilename(Call->getExprLoc()).str();
            finding.line = sourceManager.getSpellingLineNumber(Call->getExprLoc());
            finding.column = sourceManager.getSpellingColumnNumber(Call->getExprLoc());

            if (!finding.file.empty()) {
                findings.push_back(finding);
            }
        }
    }
};
} // namespace astharbor
