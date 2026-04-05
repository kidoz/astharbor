#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects functions marked `[[noreturn]]` (or `__attribute__((noreturn))`)
/// that contain a `return` statement. If a noreturn function returns, the
/// behavior is undefined per [dcl.attr.noreturn]/2.
class UbNoreturnFunctionReturnsRule : public Rule {
  public:
    std::string id() const override { return "ub/noreturn-function-returns"; }
    std::string title() const override { return "[[noreturn]] function returns"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Function marked [[noreturn]] contains a return statement — undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            functionDecl(isDefinition(), hasDescendant(returnStmt().bind("ret_stmt")))
                .bind("func"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Function = Result.Nodes.getNodeAs<clang::FunctionDecl>("func");
        const auto *ReturnStmt = Result.Nodes.getNodeAs<clang::ReturnStmt>("ret_stmt");
        if (Function == nullptr || ReturnStmt == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (!Function->isNoReturn()) {
            return;
        }
        if (isInSystemHeader(Function->getLocation(), *Result.SourceManager)) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.message = "[[noreturn]] function '" + Function->getNameAsString() +
                          "' contains a return statement — undefined behavior";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(ReturnStmt->getBeginLoc());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};

} // namespace astharbor
