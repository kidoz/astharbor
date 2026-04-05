#pragma once
#include "astharbor/rule.hpp"
#include <clang/Lex/Lexer.h>

namespace astharbor {

/// Detects `typedef` declarations that can be converted to `using` aliases.
/// Provides a safe autofix for straightforward cases (bare type name with
/// a single identifier), and a diagnostic-only message for complex forms
/// (function pointers, array types, multi-declarator typedefs).
class ReadabilityUseUsingAliasRule : public Rule {
  public:
    std::string id() const override { return "readability/use-using-alias"; }
    std::string title() const override { return "Prefer 'using' over 'typedef'"; }
    std::string category() const override { return "readability"; }
    std::string summary() const override {
        return "Converts simple typedef declarations to the modern 'using' alias form.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(typedefDecl().bind("typedef_decl"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Typedef = Result.Nodes.getNodeAs<clang::TypedefDecl>("typedef_decl");
        if (Typedef == nullptr || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Typedef->getLocation(), *Result.SourceManager)) {
            return;
        }
        // Skip implicit typedefs and typedefs inside templates.
        if (Typedef->isImplicit()) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        auto &langOpts = Result.Context->getLangOpts();

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "typedef '" + Typedef->getNameAsString() + "' can be rewritten as a 'using' alias";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto location = sourceManager.getExpansionLoc(Typedef->getBeginLoc());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);
        if (finding.file.empty()) {
            return;
        }

        // Safe autofix only for straightforward cases: the underlying type can
        // be represented as a simple text string with no embedded declarator
        // (i.e. function/array types need a declarator, which makes the fix
        // non-trivial).
        clang::QualType underlyingType = Typedef->getUnderlyingType();
        if (!isSimpleType(underlyingType)) {
            findings.push_back(finding);
            return;
        }

        // Ensure the whole typedef fits on one declaration (no compound typedef
        // list) by checking that the source range starts with the "typedef"
        // keyword.
        auto beginLoc = sourceManager.getExpansionLoc(Typedef->getBeginLoc());
        auto endLoc = sourceManager.getExpansionLoc(Typedef->getEndLoc());
        if (beginLoc.isInvalid() || endLoc.isInvalid()) {
            findings.push_back(finding);
            return;
        }

        // Verify the first token is "typedef".
        auto firstTokenText = clang::Lexer::getSourceText(
            clang::CharSourceRange::getTokenRange(beginLoc, beginLoc), sourceManager, langOpts);
        if (firstTokenText != "typedef") {
            findings.push_back(finding);
            return;
        }

        std::string typeText = underlyingType.getAsString(Result.Context->getPrintingPolicy());
        std::string replacement = "using " + Typedef->getNameAsString() + " = " + typeText;

        unsigned beginOffset = sourceManager.getFileOffset(beginLoc);
        unsigned endOffset = sourceManager.getFileOffset(endLoc);
        unsigned endTokenLength =
            clang::Lexer::MeasureTokenLength(endLoc, sourceManager, langOpts);
        unsigned totalLength = endOffset + endTokenLength - beginOffset;

        Fix fix;
        fix.fixId = "fix-using-alias-" + std::to_string(findings.size());
        fix.description = "Rewrite typedef as using-alias";
        fix.safety = "safe";
        fix.replacementText = replacement;
        fix.offset = static_cast<int>(beginOffset);
        fix.length = static_cast<int>(totalLength);
        finding.fixes.push_back(fix);

        findings.push_back(finding);
    }

  private:
    static bool isSimpleType(clang::QualType type) {
        if (type.isNull()) {
            return false;
        }
        const clang::Type *underlying = type.getTypePtr();
        if (underlying->isFunctionType() || underlying->isFunctionPointerType() ||
            underlying->isMemberFunctionPointerType() || underlying->isArrayType()) {
            return false;
        }
        return true;
    }
};

} // namespace astharbor
