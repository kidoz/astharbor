#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class PerformanceForLoopCopyRule : public Rule {
  public:
    std::string id() const override { return "performance/for-loop-copy"; }
    std::string title() const override { return "For loop copy"; }
    std::string category() const override { return "performance"; }
    std::string summary() const override { return "Range-based for loop makes an expensive copy of the loop variable."; }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        
        Finder.addMatcher(
            cxxForRangeStmt(hasLoopVariable(
                varDecl(
                    hasType(hasUnqualifiedDesugaredType(recordType())),
                    unless(hasType(referenceType()))
                ).bind("loop_var")
            )).bind("for_loop"), 
            this
        );
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        if (const auto *LoopVar = Result.Nodes.getNodeAs<clang::VarDecl>("loop_var")) {
            if (isInSystemHeader(LoopVar->getLocation(), *Result.SourceManager)) {
                return;
            }
            Finding finding;
            finding.ruleId = id();
            finding.message = "Loop variable is copied but could be a const reference (const auto&)";
            finding.severity = defaultSeverity();
            finding.category = category();

            auto &sourceManager = *Result.SourceManager;
            finding.file = sourceManager.getFilename(LoopVar->getLocation()).str();
            finding.line = sourceManager.getSpellingLineNumber(LoopVar->getLocation());
            finding.column = sourceManager.getSpellingColumnNumber(LoopVar->getLocation());

            if (!finding.file.empty()) {
                findings.push_back(finding);
            }
        }
    }
};
} // namespace astharbor
