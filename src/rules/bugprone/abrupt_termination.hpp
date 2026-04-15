#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

/// Detects calls to `std::abort()`, `std::terminate()`, or `::exit()`
/// from functions other than `main` (CERT ERR50-CPP). Library code
/// that terminates the process abruptly prevents callers from doing
/// their own cleanup or error recovery.
class BugproneAbruptTerminationRule : public Rule {
  public:
    std::string id() const override { return "bugprone/abrupt-termination"; }
    std::string title() const override { return "Abrupt termination in library code"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "abort()/terminate()/exit() called from non-main code — prevents "
               "caller cleanup.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(
                         hasAnyName("abort", "::abort", "std::abort", "::std::abort", "terminate",
                                    "::terminate", "std::terminate", "::std::terminate", "exit",
                                    "::exit", "_exit", "::_exit", "_Exit", "::_Exit"))),
                     hasAncestor(functionDecl(unless(isMain())).bind("caller")))
                .bind("term_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("term_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        const clang::FunctionDecl *callee = Call->getDirectCallee();
        const std::string calleeName = callee != nullptr ? callee->getNameAsString() : "abort";
        emitFinding(Call->getExprLoc(), *Result.SourceManager,
                    "'" + calleeName + "()' called from non-main code — prevents caller cleanup");
    }
};

} // namespace astharbor
