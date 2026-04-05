#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects single-argument non-copy/move constructors missing the `explicit`
/// keyword. Implicit single-arg constructors enable surprising conversions
/// and should generally be `explicit`. Provides a review-level autofix that
/// inserts the keyword before the constructor name.
class BestPracticeExplicitSingleArgCtorRule : public Rule {
  public:
    std::string id() const override { return "best-practice/explicit-single-arg-ctor"; }
    std::string title() const override { return "Make single-arg constructors explicit"; }
    std::string category() const override { return "best-practice"; }
    std::string summary() const override {
        return "Single-argument constructors should usually be marked 'explicit' to prevent "
               "unintended implicit conversions.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            cxxConstructorDecl(parameterCountIs(1), unless(isExplicit()), unless(isImplicit()),
                               unless(isDeleted()), unless(isDefaulted()))
                .bind("ctor"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Ctor = Result.Nodes.getNodeAs<clang::CXXConstructorDecl>("ctor");
        if (Ctor == nullptr) {
            return;
        }
        if (Ctor->isCopyConstructor() || Ctor->isMoveConstructor()) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        auto finding = makeFinding(Ctor->getLocation(), sourceManager,
                                    "Single-argument constructor '" +
                                        Ctor->getNameAsString() +
                                        "' should be marked 'explicit'");
        if (!finding) {
            return;
        }

        auto nameLoc = sourceManager.getExpansionLoc(Ctor->getLocation());
        Fix fix;
        fix.fixId = nextFixId("fix-explicit-ctor");
        fix.description = "Mark constructor as explicit";
        fix.safety = "review"; // changes implicit conversion semantics
        fix.replacementText = "explicit ";
        fix.offset = static_cast<int>(sourceManager.getFileOffset(nameLoc));
        fix.length = 0;
        finding->fixes.push_back(std::move(fix));

        findings.push_back(std::move(*finding));
    }
};

} // namespace astharbor
