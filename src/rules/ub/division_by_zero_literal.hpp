#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects division or modulo operations where the divisor is the literal 0.
/// Dividing by zero is undefined behavior per [expr.mul]/4.
class UbDivisionByZeroLiteralRule : public Rule {
  public:
    std::string id() const override { return "ub/division-by-zero-literal"; }
    std::string title() const override { return "Division by literal zero"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Division or modulo by literal zero — undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(binaryOperator(hasAnyOperatorName("/", "%"),
                                         hasRHS(ignoringParenImpCasts(integerLiteral(equals(0)))))
                              .bind("div_by_zero"),
                          this);
        // Also match compound assignments /= and %=
        Finder.addMatcher(binaryOperator(hasAnyOperatorName("/=", "%="),
                                         hasRHS(ignoringParenImpCasts(integerLiteral(equals(0)))))
                              .bind("div_by_zero"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Op = Result.Nodes.getNodeAs<clang::BinaryOperator>("div_by_zero");
        if (Op == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Op->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.message = "Division or modulo by literal zero — undefined behavior";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(Op->getExprLoc());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};

} // namespace astharbor
