#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects `sizeof(param)` where `param` is a function parameter declared
/// as an array type. Such parameters decay to pointers, so `sizeof`
/// returns the pointer size — typically leading to silent buffer-size
/// confusion and downstream out-of-bounds access.
class UbSizeofArrayParameterRule : public Rule {
  public:
    std::string id() const override { return "ub/sizeof-array-parameter"; }
    std::string title() const override { return "sizeof on decayed array parameter"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "sizeof(param) on a function parameter declared as array yields pointer size — "
               "pass an explicit length or use a span.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            unaryExprOrTypeTraitExpr(
                ofKind(clang::UETT_SizeOf),
                has(ignoringParenImpCasts(
                    declRefExpr(to(parmVarDecl().bind("param"))).bind("ref"))))
                .bind("sizeof_expr"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *SizeofExpr =
            Result.Nodes.getNodeAs<clang::UnaryExprOrTypeTraitExpr>("sizeof_expr");
        const auto *Param = Result.Nodes.getNodeAs<clang::ParmVarDecl>("param");
        if (SizeofExpr == nullptr || Param == nullptr) {
            return;
        }
        // Look at the *original* declared type of the parameter: if the
        // source wrote `T arr[N]`, the decl's type is already decayed to
        // `T*`, but the source-info retains the array form.
        clang::QualType paramType = Param->getType();
        if (!paramType->isPointerType()) {
            return;
        }
        auto typeSourceInfo = Param->getTypeSourceInfo();
        if (typeSourceInfo == nullptr) {
            return;
        }
        // Walk the TypeLoc to see if the spelled type was an array.
        clang::TypeLoc typeLoc = typeSourceInfo->getTypeLoc();
        if (typeLoc.getTypePtr()->isArrayType() == false) {
            // Check for the "adjusted" type pattern used by function
            // parameters: DecayedType wraps the original ArrayType.
            const clang::Type *original = Param->getOriginalType().getTypePtr();
            if (!original->isArrayType()) {
                return;
            }
        }

        emitFinding(SizeofExpr->getExprLoc(), *Result.SourceManager,
                    "sizeof() on parameter '" + Param->getNameAsString() +
                        "' returns the pointer size, not the array size — the array decays on "
                        "function entry");
    }
};

} // namespace astharbor
