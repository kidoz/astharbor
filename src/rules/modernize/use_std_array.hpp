#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

class ModernizeUseStdArrayRule : public Rule {
  public:
    std::string id() const override { return "modernize/use-std-array"; }
    std::string title() const override { return "Use std::array"; }
    std::string category() const override { return "modernize"; }
    std::string summary() const override {
        return "Local fixed-size C arrays in C++ can usually be expressed as std::array.";
    }
    std::string defaultSeverity() const override { return "note"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            varDecl(hasLocalStorage(), hasType(constantArrayType()), unless(parmVarDecl()))
                .bind("array_var"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Var = Result.Nodes.getNodeAs<clang::VarDecl>("array_var");
        if (Var == nullptr || Result.SourceManager == nullptr || Result.Context == nullptr ||
            !Result.Context->getLangOpts().CPlusPlus) {
            return;
        }
        if (isInSystemHeader(Var->getLocation(), *Result.SourceManager)) {
            return;
        }
        emitFinding(Var->getLocation(), *Result.SourceManager,
                    "Local fixed-size array '" + Var->getNameAsString() +
                        "' can usually be replaced with std::array");
    }
};

} // namespace astharbor
