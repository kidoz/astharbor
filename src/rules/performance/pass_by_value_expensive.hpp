#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

class PerformancePassByValueExpensiveRule : public Rule {
  public:
    std::string id() const override { return "performance/pass-by-value-expensive"; }
    std::string title() const override { return "Expensive pass by value"; }
    std::string category() const override { return "performance"; }
    std::string summary() const override {
        return "Large record parameter is passed by value; prefer const reference when ownership "
               "is not needed.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(parmVarDecl(unless(hasType(referenceType())),
                                      unless(hasType(pointerType())),
                                      hasType(hasUnqualifiedDesugaredType(recordType())))
                              .bind("param"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Param = Result.Nodes.getNodeAs<clang::ParmVarDecl>("param");
        if (Param == nullptr || Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Param->getLocation(), *Result.SourceManager)) {
            return;
        }
        const clang::QualType type = Param->getType().getCanonicalType();
        if (type.isNull() || type->isIncompleteType()) {
            return;
        }
        const uint64_t sizeBits = Result.Context->getTypeSize(type);
        if (sizeBits <= 128) {
            return;
        }
        emitFinding(Param->getLocation(), *Result.SourceManager,
                    "Large parameter '" + Param->getNameAsString() +
                        "' is passed by value; prefer const reference unless a copy is required");
    }
};

} // namespace astharbor
