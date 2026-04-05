#pragma once
#include "astharbor/rule.hpp"
#include <clang/Lex/Lexer.h>

namespace astharbor {

/// Detects single-argument non-copy/move constructors missing the `explicit`
/// keyword. Implicit single-arg constructors enable surprising conversions
/// and should generally be `explicit`. Provides a review-level autofix that
/// inserts the `explicit` keyword.
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
            cxxConstructorDecl(parameterCountIs(1), unless(isExplicit()), unless(isImplicit()))
                .bind("ctor"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Ctor = Result.Nodes.getNodeAs<clang::CXXConstructorDecl>("ctor");
        if (Ctor == nullptr || Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Ctor->getLocation(), *Result.SourceManager)) {
            return;
        }
        // Copy/move constructors should not be `explicit`.
        if (Ctor->isCopyConstructor() || Ctor->isMoveConstructor()) {
            return;
        }
        // Skip deleted, defaulted, and inherited constructors.
        if (Ctor->isDeleted() || Ctor->isDefaulted() ||
            llvm::isa<clang::CXXConstructorDecl>(Ctor) == false) {
            return;
        }
        // Skip constructors where the single parameter has a default value
        // (still a valid signature but rarer false-positive surface).
        const clang::ParmVarDecl *param = Ctor->getParamDecl(0);
        if (param == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        auto &langOpts = Result.Context->getLangOpts();

        Finding finding;
        finding.ruleId = id();
        finding.message = "Single-argument constructor '" + Ctor->getNameAsString() +
                          "' should be marked 'explicit'";
        finding.severity = defaultSeverity();
        finding.category = category();
        auto location = sourceManager.getExpansionLoc(Ctor->getLocation());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);
        if (finding.file.empty()) {
            return;
        }

        // Insert `explicit ` before the constructor name. The name location
        // points to the identifier itself.
        auto nameLoc = sourceManager.getExpansionLoc(Ctor->getLocation());
        if (nameLoc.isValid()) {
            unsigned insertOffset = sourceManager.getFileOffset(nameLoc);
            Fix fix;
            fix.fixId = "fix-explicit-ctor-" + std::to_string(findings.size());
            fix.description = "Mark constructor as explicit";
            fix.safety = "review"; // changes implicit conversion semantics
            fix.replacementText = "explicit ";
            fix.offset = static_cast<int>(insertOffset);
            fix.length = 0;
            finding.fixes.push_back(fix);
        }

        findings.push_back(finding);
        (void)langOpts;
    }
};

} // namespace astharbor
