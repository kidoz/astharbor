#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Attr.h>
#include <clang/AST/TypeLoc.h>
#include <clang/Basic/TokenKinds.h>
#include <clang/Lex/Lexer.h>

namespace astharbor {
class ModernizeUseOverrideRule : public Rule {
  public:
    std::string id() const override { return "modernize/use-override"; }
    std::string title() const override { return "Use override"; }
    std::string category() const override { return "modernize"; }
    std::string summary() const override {
        return "Requires 'override' keyword on overridden virtual functions.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(cxxMethodDecl(isOverride()).bind("method"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Method = Result.Nodes.getNodeAs<clang::CXXMethodDecl>("method");
        if (Method == nullptr || Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Method->getLocation(), *Result.SourceManager)) {
            return;
        }
        if (Method->hasAttr<clang::OverrideAttr>() || Method->isImplicit()) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "Virtual function overrides a base class method but lacks 'override' keyword";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto &langOpts = Result.Context->getLangOpts();
        finding.file = sourceManager.getFilename(Method->getLocation()).str();
        finding.line = sourceManager.getSpellingLineNumber(Method->getLocation());
        finding.column = sourceManager.getSpellingColumnNumber(Method->getLocation());
        if (finding.file.empty()) {
            return;
        }

        // Try to compute a safe insertion point for " override" past the closing
        // paren of the parameter list and any cv/ref/noexcept qualifiers.
        if (auto insertOffset = computeOverrideInsertOffset(*Method, sourceManager, langOpts)) {
            Fix fix;
            fix.fixId = "fix-override-" + std::to_string(findings.size());
            fix.description = "Add 'override' keyword";
            fix.safety = "safe";
            fix.replacementText = " override";
            fix.offset = static_cast<int>(*insertOffset);
            fix.length = 0;
            finding.fixes.push_back(fix);
        }

        findings.push_back(finding);
    }

  private:
    /// Walk tokens after the closing paren of the function's parameter list,
    /// skipping cv-qualifiers, ref-qualifiers, and bare `noexcept`. Returns the
    /// file offset where " override" should be inserted, or nullopt if the
    /// function signature is too complex to handle safely.
    static std::optional<unsigned>
    computeOverrideInsertOffset(const clang::CXXMethodDecl &Method,
                                const clang::SourceManager &sourceManager,
                                const clang::LangOptions &langOpts) {
        auto functionTypeLoc = Method.getFunctionTypeLoc();
        if (!functionTypeLoc) {
            return std::nullopt;
        }
        clang::SourceLocation rparenLoc = functionTypeLoc.getRParenLoc();
        if (rparenLoc.isInvalid()) {
            return std::nullopt;
        }

        // Scan tokens after the closing `)`. Lexer::findNextToken internally
        // advances past the token at its input location, so we pass the raw
        // `rparenLoc` and let it find the next real token. For subsequent
        // iterations we pass the *start* location of the token we just saw so
        // findNextToken advances past it. Keyword tokens arrive as
        // raw_identifier under raw lexing — we match them by spelling.
        clang::SourceLocation scanLoc = rparenLoc;
        clang::SourceLocation insertLoc =
            clang::Lexer::getLocForEndOfToken(rparenLoc, 0, sourceManager, langOpts);

        for (int steps = 0; steps < 16; ++steps) {
            auto token = clang::Lexer::findNextToken(scanLoc, sourceManager, langOpts);
            if (!token) {
                return std::nullopt;
            }
            clang::tok::TokenKind kind = token->getKind();

            // Terminators — insert at current insertLoc, before this token.
            if (kind == clang::tok::semi || kind == clang::tok::l_brace ||
                kind == clang::tok::equal || kind == clang::tok::arrow) {
                return sourceManager.getFileOffset(insertLoc);
            }

            // Ref-qualifiers via punctuation.
            if (kind == clang::tok::amp || kind == clang::tok::ampamp) {
                scanLoc = token->getLocation();
                insertLoc = clang::Lexer::getLocForEndOfToken(token->getLocation(), 0,
                                                              sourceManager, langOpts);
                continue;
            }

            // cv-qualifiers and bare `noexcept` arrive as raw_identifier.
            if (kind == clang::tok::raw_identifier || kind == clang::tok::identifier) {
                auto spelling = clang::Lexer::getSpelling(*token, sourceManager, langOpts);
                if (spelling == "const" || spelling == "volatile" ||
                    spelling == "noexcept") {
                    scanLoc = token->getLocation();
                    insertLoc = clang::Lexer::getLocForEndOfToken(token->getLocation(), 0,
                                                                  sourceManager, langOpts);
                    continue;
                }
                if (spelling == "final") {
                    // Insert before `final`.
                    return sourceManager.getFileOffset(insertLoc);
                }
            }

            // Anything else (e.g. noexcept(expr), throw(...), trailing return) —
            // bail to avoid producing a broken fix.
            return std::nullopt;
        }
        return std::nullopt;
    }
};
} // namespace astharbor
