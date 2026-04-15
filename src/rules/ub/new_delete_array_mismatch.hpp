#pragma once
#include "astharbor/rule.hpp"
#include <clang/Lex/Lexer.h>

namespace astharbor {

/// Detects `delete` paired with array `new` (or vice versa) on the same
/// variable. Mismatched new/delete forms cause undefined behavior per
/// [expr.delete]/2. Provides a safe autofix when `new[]` is paired with
/// scalar `delete` (adds the `[]`).
class UbNewDeleteArrayMismatchRule : public Rule {
  public:
    std::string id() const override { return "ub/new-delete-array-mismatch"; }
    std::string title() const override { return "new[]/delete form mismatch"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Mismatched new[]/delete or new/delete[] forms — undefined behavior.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // Delete expressions typically wrap their operand in an
        // LValueToRValue ImplicitCastExpr, so `has()` alone is too strict —
        // use `hasDescendant` to reach the DeclRefExpr through the cast.
        Finder.addMatcher(
            cxxDeleteExpr(hasDescendant(declRefExpr(to(varDecl(hasInitializer(ignoringParenImpCasts(
                                                                   cxxNewExpr().bind("new_expr"))))
                                                           .bind("var")))))
                .bind("delete_expr"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *DeleteExpr = Result.Nodes.getNodeAs<clang::CXXDeleteExpr>("delete_expr");
        const auto *NewExpr = Result.Nodes.getNodeAs<clang::CXXNewExpr>("new_expr");
        if (DeleteExpr == nullptr || NewExpr == nullptr || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(DeleteExpr->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        bool newIsArray = NewExpr->isArray();
        bool deleteIsArray = DeleteExpr->isArrayForm();
        if (newIsArray == deleteIsArray) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.severity = defaultSeverity();
        finding.category = category();
        if (newIsArray && !deleteIsArray) {
            finding.message = "Array allocated with 'new[]' is deleted with scalar 'delete' — "
                              "undefined behavior";
        } else {
            finding.message = "Scalar allocated with 'new' is deleted with array 'delete[]' — "
                              "undefined behavior";
        }

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(DeleteExpr->getExprLoc());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);
        if (finding.file.empty()) {
            return;
        }

        // Safe autofix for the common "new[] ... delete" case: replace the
        // `delete` keyword with `delete[]`.
        if (newIsArray && !deleteIsArray) {
            auto keywordLoc = sourceManager.getExpansionLoc(DeleteExpr->getBeginLoc());
            unsigned keywordOffset = sourceManager.getFileOffset(keywordLoc);
            unsigned keywordLength = clang::Lexer::MeasureTokenLength(
                keywordLoc, sourceManager, Result.Context->getLangOpts());
            if (keywordLength == 6) { // "delete"
                Fix fix;
                fix.fixId = "fix-delete-array-" + std::to_string(findings.size());
                fix.description = "Change 'delete' to 'delete[]' to match 'new[]'";
                fix.safety = "safe";
                fix.replacementText = "delete[]";
                fix.offset = static_cast<int>(keywordOffset);
                fix.length = static_cast<int>(keywordLength);
                finding.fixes.push_back(fix);
            }
        }

        findings.push_back(finding);
    }
};

} // namespace astharbor
