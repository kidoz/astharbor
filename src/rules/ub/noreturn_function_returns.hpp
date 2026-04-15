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
        // Filter to noreturn functions at matching time so the engine does
        // not visit every function body in the TU just to reject them.
        Finder.addMatcher(
            functionDecl(isDefinition(), isNoReturn(), hasDescendant(returnStmt().bind("ret_stmt")))
                .bind("func"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Function = Result.Nodes.getNodeAs<clang::FunctionDecl>("func");
        const auto *ReturnStmt = Result.Nodes.getNodeAs<clang::ReturnStmt>("ret_stmt");
        if (Function == nullptr || ReturnStmt == nullptr) {
            return;
        }
        emitFinding(ReturnStmt->getBeginLoc(), *Result.SourceManager,
                    "[[noreturn]] function '" + Function->getNameAsString() +
                        "' contains a return statement — undefined behavior");
    }
};

} // namespace astharbor
