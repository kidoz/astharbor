#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Attr.h>

namespace astharbor {
class ModernizeUseOverrideRule : public Rule {
  public:
    std::string id() const override { return "modernize/use-override"; }
    std::string title() const override { return "Use override"; }
    std::string category() const override { return "modernize"; }
    std::string summary() const override { return "Requires 'override' keyword on overridden virtual functions."; }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(cxxMethodDecl(isOverride()).bind("method"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        if (const auto *Method = Result.Nodes.getNodeAs<clang::CXXMethodDecl>("method")) {
            if (isInSystemHeader(Method->getLocation(), *Result.SourceManager)) {
                return;
            }
            if (!Method->hasAttr<clang::OverrideAttr>()) {
                if (!Method->isImplicit()) {
                    Finding finding;
                    finding.ruleId = id();
                    finding.message = "Virtual function overrides a base class method but lacks 'override' keyword";
                    finding.severity = defaultSeverity();
                    finding.category = category();

                    auto &sourceManager = *Result.SourceManager;
                    finding.file = sourceManager.getFilename(Method->getLocation()).str();
                    finding.line = sourceManager.getSpellingLineNumber(Method->getLocation());
                    finding.column = sourceManager.getSpellingColumnNumber(Method->getLocation());

                    if (!finding.file.empty()) {
                        findings.push_back(finding);
                    }
                }
            }
        }
    }
};
} // namespace astharbor
