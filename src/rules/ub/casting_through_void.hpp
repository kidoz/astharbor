#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects two-step casts `static_cast<T*>(static_cast<void*>(x))` that are
/// often used to deliberately circumvent the strict-aliasing rule. The
/// resulting pointer still violates aliasing if dereferenced.
/// Mirrors clang-tidy `bugprone-casting-through-void`.
class UbCastingThroughVoidRule : public Rule {
  public:
    std::string id() const override { return "ub/casting-through-void"; }
    std::string title() const override { return "Cast through void*"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Cast chain T* -> void* -> U* circumvents strict aliasing — the dereferenced "
               "result is still undefined behavior.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // Outer explicit cast to a non-void pointer, whose immediate operand
        // is another explicit cast to a void pointer.
        auto innerCastToVoid = explicitCastExpr(hasDestinationType(pointsTo(voidType())));
        Finder.addMatcher(
            explicitCastExpr(hasDestinationType(pointsTo(qualType(unless(voidType())))),
                             hasSourceExpression(ignoringParenImpCasts(innerCastToVoid)))
                .bind("outer_cast"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Cast = Result.Nodes.getNodeAs<clang::ExplicitCastExpr>("outer_cast");
        if (Cast == nullptr) {
            return;
        }
        emitFinding(Cast->getExprLoc(), *Result.SourceManager,
                    "Cast chain through void* circumvents strict aliasing — dereferencing the "
                    "result is undefined behavior");
    }
};

} // namespace astharbor
