#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/DeclCXX.h>

namespace astharbor {

/// Detects copy constructors whose source parameter is a non-const
/// reference (CERT OOP58-CPP):
///
///     struct T { T(T &other); };   // bug: can mutate the source
///
/// The fix is `T(const T &other)`.
class BugproneCopyCtorNonConstRule : public Rule {
  public:
    std::string id() const override { return "bugprone/copy-ctor-non-const"; }
    std::string title() const override { return "Copy ctor takes non-const source"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Copy constructor parameter is a non-const reference — can "
               "silently mutate the source object.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            cxxConstructorDecl(
                isCopyConstructor(),
                hasParameter(0, parmVarDecl(hasType(
                    lValueReferenceType(unless(pointee(isConstQualified())))))))
                .bind("bad_copy_ctor"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Ctor =
            Result.Nodes.getNodeAs<clang::CXXConstructorDecl>("bad_copy_ctor");
        if (Ctor == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Ctor->getLocation(), *Result.SourceManager)) {
            return;
        }
        emitFinding(Ctor->getLocation(), *Result.SourceManager,
                    "Copy constructor of '" +
                        Ctor->getParent()->getNameAsString() +
                        "' takes a non-const reference — use 'const " +
                        Ctor->getParent()->getNameAsString() + " &'");
    }
};

} // namespace astharbor
