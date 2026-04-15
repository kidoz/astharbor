#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects C-style casts `(T*)expr` between unrelated non-byte pointer
/// types. Same strict-aliasing concern as `reinterpret_cast`, harder to
/// spot in code review. See [basic.lval]/11.
class UbCStyleCastPointerPunningRule : public Rule {
  public:
    std::string id() const override { return "ub/c-style-cast-pointer-punning"; }
    std::string title() const override { return "C-style cast pointer punning"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "C-style cast between unrelated pointer types violates strict aliasing — use "
               "std::memcpy or std::bit_cast.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(cStyleCastExpr().bind("cast"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Cast = Result.Nodes.getNodeAs<clang::CStyleCastExpr>("cast");
        if (Cast == nullptr) {
            return;
        }
        clang::QualType destinationType = Cast->getType();
        clang::QualType sourceType = Cast->getSubExpr()->getType();
        if (!destinationType->isPointerType() || !sourceType->isPointerType()) {
            return;
        }
        clang::QualType destinationPointee = destinationType->getPointeeType();
        clang::QualType sourcePointee = sourceType->getPointeeType();
        if (isByteLikeOrVoid(destinationPointee) || isByteLikeOrVoid(sourcePointee)) {
            return;
        }
        if (destinationPointee->isFunctionType() || sourcePointee->isFunctionType()) {
            return;
        }
        if (destinationPointee.getUnqualifiedType() == sourcePointee.getUnqualifiedType()) {
            return;
        }
        const clang::CXXRecordDecl *destinationRecord = destinationPointee->getAsCXXRecordDecl();
        const clang::CXXRecordDecl *sourceRecord = sourcePointee->getAsCXXRecordDecl();
        if (destinationRecord != nullptr && sourceRecord != nullptr &&
            destinationRecord->hasDefinition() && sourceRecord->hasDefinition()) {
            if (destinationRecord->isDerivedFrom(sourceRecord) ||
                sourceRecord->isDerivedFrom(destinationRecord)) {
                return;
            }
        }

        emitFinding(Cast->getExprLoc(), *Result.SourceManager,
                    "C-style cast between unrelated pointer types '" + sourcePointee.getAsString() +
                        " *' and '" + destinationPointee.getAsString() +
                        " *' — likely strict-aliasing violation; use std::memcpy or "
                        "std::bit_cast");
    }

  private:
    static bool isByteLikeOrVoid(clang::QualType type) {
        if (type.isNull()) {
            return true;
        }
        clang::QualType unqualified = type.getUnqualifiedType();
        if (unqualified->isVoidType() || unqualified->isCharType()) {
            return true;
        }
        if (const auto *enumType = unqualified->getAs<clang::EnumType>()) {
            if (const auto *enumDecl = enumType->getDecl()) {
                return enumDecl->getName() == "byte";
            }
        }
        return false;
    }
};

} // namespace astharbor
