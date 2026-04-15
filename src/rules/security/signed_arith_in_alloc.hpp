#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecuritySignedArithInAllocRule : public Rule {
  public:
    std::string id() const override { return "security/signed-arith-in-alloc"; }
    std::string title() const override { return "Signed arithmetic in allocation"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects signed integer arithmetic used as a size argument to allocation functions, "
               "which can overflow and cause under-allocation.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("malloc", "calloc", "realloc", "reallocarray",
                                                    "::malloc", "::calloc", "::realloc",
                                                    "std::malloc", "std::calloc", "std::realloc"))),
                     hasAnyArgument(ignoringParenImpCasts(
                         binaryOperator(hasAnyOperatorName("+", "*", "-")).bind("signed_arith"))))
                .bind("alloc_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *ArithOp = Result.Nodes.getNodeAs<clang::BinaryOperator>("signed_arith");
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("alloc_call");
        if (ArithOp == nullptr || Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        clang::QualType LeftType = ArithOp->getLHS()->IgnoreParenImpCasts()->getType();
        clang::QualType RightType = ArithOp->getRHS()->IgnoreParenImpCasts()->getType();

        bool HasSignedOperand =
            (LeftType->isSignedIntegerType() || RightType->isSignedIntegerType());

        if (!HasSignedOperand) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "Signed integer arithmetic used as allocation size — signed overflow is undefined "
            "behavior and can cause under-allocation (CWE-190)";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(ArithOp->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(ArithOp->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(ArithOp->getExprLoc());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};
} // namespace astharbor
