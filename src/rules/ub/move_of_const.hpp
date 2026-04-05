#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects calls to `std::move` on a const-qualified lvalue. Such calls
/// resolve to `const T&&` which matches copy constructors instead of move
/// constructors — the "move" silently becomes a copy. Not strict-sense UB
/// but a frequent defect that defeats the caller's intent.
class UbMoveOfConstRule : public Rule {
  public:
    std::string id() const override { return "ub/move-of-const"; }
    std::string title() const override { return "std::move on const object"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "std::move on a const lvalue silently copies instead of moving.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // `std::move` is a function template; callers spell it variously
        // (`std::move`, `::std::move`). Match by unqualified name inside the
        // `std` namespace to cover all spellings.
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasName("move"),
                                          hasDeclContext(namespaceDecl(hasName("std"))))),
                     hasArgument(0, expr().bind("arg")))
                .bind("move_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("move_call");
        const auto *Arg = Result.Nodes.getNodeAs<clang::Expr>("arg");
        if (Call == nullptr || Arg == nullptr) {
            return;
        }
        clang::QualType argType = Arg->IgnoreParenImpCasts()->getType();
        if (!argType.isConstQualified()) {
            return;
        }
        // Reference-to-const is the usual form — also catches plain const T.
        emitFinding(Call->getExprLoc(), *Result.SourceManager,
                    "std::move on a const-qualified object silently copies instead of "
                    "moving — drop the std::move or remove const");
    }
};

} // namespace astharbor
