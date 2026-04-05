#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects non-void functions that lack any `return` statement in their body.
/// Flowing off the end of a value-returning function is undefined behavior
/// per [stmt.return]/2 (except for `main`, which has an implicit `return 0`).
class UbMissingReturnInNonVoidRule : public Rule {
  public:
    std::string id() const override { return "ub/missing-return-in-non-void"; }
    std::string title() const override { return "Missing return in non-void function"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Non-void function with no return statement — flowing off the end is UB.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            functionDecl(isDefinition(), unless(returns(voidType())), unless(isMain()),
                         unless(hasDescendant(returnStmt())))
                .bind("missing_return_func"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Function =
            Result.Nodes.getNodeAs<clang::FunctionDecl>("missing_return_func");
        if (Function == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Function->getLocation(), *Result.SourceManager)) {
            return;
        }
        // Skip constructors, destructors, conversion operators, deleted/defaulted
        if (llvm::isa<clang::CXXConstructorDecl>(Function) ||
            llvm::isa<clang::CXXDestructorDecl>(Function) ||
            Function->isDeleted() || Function->isDefaulted()) {
            return;
        }
        // Skip if the return type is dependent (templates)
        if (Function->getReturnType()->isDependentType()) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.message = "Non-void function '" + Function->getNameAsString() +
                          "' has no return statement; flowing off the end is undefined behavior";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(Function->getLocation());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};

} // namespace astharbor
