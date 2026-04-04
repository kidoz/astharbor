#pragma once
#include "astharbor/rule.hpp"
#include <clang/Lex/Lexer.h>

namespace astharbor {
class ModernizeUseNullptrRule : public Rule {
  public:
    std::string id() const override { return "modernize/use-nullptr"; }
    std::string title() const override { return "Use nullptr"; }
    std::string category() const override { return "modernize"; }
    std::string summary() const override { return "Detects NULL and suggests nullptr."; }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(castExpr(hasCastKind(clang::CK_NullToPointer),
                                   unless(hasSourceExpression(cxxNullPtrLiteralExpr())))
                              .bind("null_cast"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        if (const auto *CastNode = Result.Nodes.getNodeAs<clang::CastExpr>("null_cast")) {
            if (isInSystemHeader(CastNode->getBeginLoc(), *Result.SourceManager)) {
                return;
            }

            auto &sourceManager = *Result.SourceManager;
            auto &langOpts = Result.Context->getLangOpts();
            auto expansionLoc = sourceManager.getExpansionLoc(CastNode->getBeginLoc());
            auto endExpansionLoc = sourceManager.getExpansionLoc(CastNode->getEndLoc());

            Finding finding;
            finding.ruleId = id();
            finding.message = "Use nullptr instead of NULL";
            finding.severity = defaultSeverity();
            finding.category = category();
            finding.file = sourceManager.getFilename(expansionLoc).str();
            finding.line = sourceManager.getSpellingLineNumber(expansionLoc);
            finding.column = sourceManager.getSpellingColumnNumber(expansionLoc);

            if (!finding.file.empty()) {
                unsigned beginOffset = sourceManager.getFileOffset(expansionLoc);
                unsigned endOffset = sourceManager.getFileOffset(endExpansionLoc);
                unsigned tokenLength =
                    clang::Lexer::MeasureTokenLength(endExpansionLoc, sourceManager, langOpts);
                unsigned totalLength = endOffset - beginOffset + tokenLength;

                Fix fix;
                fix.fixId = "fix-nullptr-" + std::to_string(findings.size());
                fix.description = "Replace NULL/0 with nullptr";
                fix.safety = "safe";
                fix.replacementText = "nullptr";
                fix.offset = static_cast<int>(beginOffset);
                fix.length = static_cast<int>(totalLength);
                finding.fixes.push_back(fix);

                findings.push_back(finding);
            }
        }
    }
};
} // namespace astharbor
