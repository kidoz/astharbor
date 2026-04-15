#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class ReadabilityConstReturnTypeRule : public Rule {
  public:
    std::string id() const override { return "readability/const-return-type"; }
    std::string title() const override { return "Const return type"; }
    std::string category() const override { return "readability"; }
    std::string summary() const override {
        return "Functions should not return const value types.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // Match functions returning a const-qualified type
        Finder.addMatcher(functionDecl(returns(isConstQualified())).bind("func"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        if (const auto *Function = Result.Nodes.getNodeAs<clang::FunctionDecl>("func")) {
            if (isInSystemHeader(Function->getLocation(), *Result.SourceManager)) {
                return;
            }
            clang::QualType ReturnType = Function->getReturnType();
            // Check if it's a local const qualification on a value type (not pointer/ref)
            if (ReturnType.isLocalConstQualified() && !ReturnType->isReferenceType() &&
                !ReturnType->isPointerType()) {
                Finding finding;
                finding.ruleId = id();
                finding.message =
                    "Return type is const-qualified value, which inhibits move semantics";
                finding.severity = defaultSeverity();
                finding.category = category();

                auto &sourceManager = *Result.SourceManager;
                finding.file = sourceManager.getFilename(Function->getLocation()).str();
                finding.line = sourceManager.getSpellingLineNumber(Function->getLocation());
                finding.column = sourceManager.getSpellingColumnNumber(Function->getLocation());

                if (!finding.file.empty()) {
                    findings.push_back(finding);
                }
            }
        }
    }
};
} // namespace astharbor
