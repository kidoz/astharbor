#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects `reinterpret_cast` between pointers to unrelated non-char types.
/// Accessing an object through a pointer of the wrong type violates the
/// strict aliasing rule and is undefined behavior per [basic.lval]/11.
class UbReinterpretCastTypePunningRule : public Rule {
  public:
    std::string id() const override { return "ub/reinterpret-cast-type-punning"; }
    std::string title() const override { return "reinterpret_cast type punning"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "reinterpret_cast between unrelated pointer types violates strict aliasing — "
               "use std::memcpy or std::bit_cast.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(cxxReinterpretCastExpr().bind("cast"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Cast =
            Result.Nodes.getNodeAs<clang::CXXReinterpretCastExpr>("cast");
        if (Cast == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Cast->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        clang::QualType destinationType = Cast->getType();
        clang::QualType sourceType = Cast->getSubExpr()->getType();
        if (!destinationType->isPointerType() || !sourceType->isPointerType()) {
            return;
        }

        clang::QualType destinationPointee = destinationType->getPointeeType();
        clang::QualType sourcePointee = sourceType->getPointeeType();

        // Both casts to/from byte-like types are permitted by the standard.
        if (isByteLike(destinationPointee) || isByteLike(sourcePointee)) {
            return;
        }
        // void* casts are common and usually intentional interface boundaries.
        if (destinationPointee->isVoidType() || sourcePointee->isVoidType()) {
            return;
        }
        // Function pointer casts are a separate concern (different UB category).
        if (destinationPointee->isFunctionType() || sourcePointee->isFunctionType()) {
            return;
        }
        // Same unqualified type — no punning.
        if (destinationPointee.getUnqualifiedType() == sourcePointee.getUnqualifiedType()) {
            return;
        }
        // Related types via inheritance are typically intentional (dynamic_cast
        // alternative in hot paths). Skip when one is a base of the other.
        const clang::CXXRecordDecl *destinationRecord = destinationPointee->getAsCXXRecordDecl();
        const clang::CXXRecordDecl *sourceRecord = sourcePointee->getAsCXXRecordDecl();
        if (destinationRecord != nullptr && sourceRecord != nullptr) {
            if (destinationRecord->hasDefinition() && sourceRecord->hasDefinition()) {
                if (destinationRecord->isDerivedFrom(sourceRecord) ||
                    sourceRecord->isDerivedFrom(destinationRecord)) {
                    return;
                }
            }
        }

        Finding finding;
        finding.ruleId = id();
        finding.message = "reinterpret_cast between unrelated pointer types '" +
                          sourcePointee.getAsString() + " *' and '" +
                          destinationPointee.getAsString() +
                          " *' — likely strict-aliasing violation; use std::memcpy or "
                          "std::bit_cast";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(Cast->getExprLoc());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }

  private:
    static bool isByteLike(clang::QualType type) {
        if (type.isNull()) {
            return false;
        }
        clang::QualType unqualified = type.getUnqualifiedType();
        if (unqualified->isCharType()) {
            return true;
        }
        // std::byte is a scoped enum in <cstddef>. Check via EnumDecl to
        // avoid allocating a std::string on every hot-path match.
        if (const auto *enumType = unqualified->getAs<clang::EnumType>()) {
            if (const auto *enumDecl = enumType->getDecl()) {
                llvm::StringRef name = enumDecl->getName();
                if (name == "byte") {
                    return true;
                }
            }
        }
        return false;
    }
};

} // namespace astharbor
