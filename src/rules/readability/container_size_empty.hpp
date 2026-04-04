#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class ReadabilityContainerSizeEmptyRule : public Rule {
  public:
    std::string id() const override { return "readability/container-size-empty"; }
    std::string title() const override { return "Container size empty"; }
    std::string category() const override { return "readability"; }
    std::string summary() const override { return "Checks whether a container's size is being compared to zero rather than using empty()."; }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        
        auto SizeCall = cxxMemberCallExpr(callee(cxxMethodDecl(hasName("size")))).bind("size_call");
        auto ZeroLiteral = integerLiteral(equals(0));

        Finder.addMatcher(
            binaryOperator(
                hasAnyOperatorName("==", "!=", ">", "<", ">=", "<="),
                hasEitherOperand(SizeCall),
                hasEitherOperand(ZeroLiteral)
            ).bind("op"),
            this
        );
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        if (const auto *Call = Result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("size_call")) {
            if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
                return;
            }
            Finding finding;
            finding.ruleId = id();
            finding.message = "Use empty() instead of checking size() against 0";
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
