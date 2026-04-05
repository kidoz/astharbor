#pragma once
#include "astharbor/rule.hpp"
#include <clang/Lex/Lexer.h>

namespace astharbor {
class ReadabilityContainerSizeEmptyRule : public Rule {
  public:
    std::string id() const override { return "readability/container-size-empty"; }
    std::string title() const override { return "Container size empty"; }
    std::string category() const override { return "readability"; }
    std::string summary() const override {
        return "Checks whether a container's size is being compared to zero rather than using "
               "empty().";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;

        auto sizeCall =
            cxxMemberCallExpr(callee(cxxMethodDecl(hasName("size")))).bind("size_call");
        auto zeroLiteral = integerLiteral(equals(0));

        Finder.addMatcher(
            binaryOperator(hasAnyOperatorName("==", "!=", ">", "<", ">=", "<="),
                           hasEitherOperand(ignoringParenImpCasts(sizeCall)),
                           hasEitherOperand(ignoringParenImpCasts(zeroLiteral)))
                .bind("op"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("size_call");
        const auto *Op = Result.Nodes.getNodeAs<clang::BinaryOperator>("op");
        if (Call == nullptr || Op == nullptr || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Op->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        auto &langOpts = Result.Context->getLangOpts();

        Finding finding;
        finding.ruleId = id();
        finding.message = "Use empty() instead of checking size() against 0";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(Op->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(Op->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(Op->getExprLoc());
        if (finding.file.empty()) {
            return;
        }

        // Determine whether the comparison means "empty" (→ .empty()) or
        // "not empty" (→ !.empty()).
        clang::BinaryOperator::Opcode opcode = Op->getOpcode();
        bool sizeIsLhs = isSizeCall(Op->getLHS());
        std::optional<bool> wantNegation = classifyComparison(opcode, sizeIsLhs);
        if (!wantNegation) {
            // Trivially true/false comparisons (>=0, <0) — still diagnose but
            // don't auto-fix.
            findings.push_back(finding);
            return;
        }

        // Get the source text of the container object ("container" in
        // "container.size() == 0"). This supports bare identifiers, member
        // accesses, pointer derefs, etc. as long as the text is reconstructible.
        const clang::Expr *objectExpr = Call->getImplicitObjectArgument();
        if (objectExpr == nullptr) {
            findings.push_back(finding);
            return;
        }
        objectExpr = objectExpr->IgnoreParenImpCasts();
        auto objectRange = clang::CharSourceRange::getTokenRange(objectExpr->getSourceRange());
        llvm::StringRef objectText =
            clang::Lexer::getSourceText(objectRange, sourceManager, langOpts);
        if (objectText.empty()) {
            findings.push_back(finding);
            return;
        }
        // For pointer-like objects (`->size()`), the implicit object is a
        // dereference and the source range covers just the pointer expression.
        // Pick the appropriate member-access operator.
        bool isPointerAccess = Call->getImplicitObjectArgument()
                                   ->IgnoreParenImpCasts()
                                   ->getType()
                                   ->isPointerType();
        std::string accessor = isPointerAccess ? "->" : ".";

        std::string replacement = (wantNegation.value() ? "!" : "") + objectText.str() +
                                  accessor + "empty()";

        // Compute the source range of the full binary expression to replace.
        auto beginLoc = sourceManager.getExpansionLoc(Op->getBeginLoc());
        auto endLoc = sourceManager.getExpansionLoc(Op->getEndLoc());
        unsigned beginOffset = sourceManager.getFileOffset(beginLoc);
        unsigned endOffset = sourceManager.getFileOffset(endLoc);
        unsigned endTokenLength =
            clang::Lexer::MeasureTokenLength(endLoc, sourceManager, langOpts);
        unsigned totalLength = endOffset + endTokenLength - beginOffset;

        Fix fix;
        fix.fixId = "fix-size-empty-" + std::to_string(findings.size());
        fix.description = "Replace size() comparison with empty()";
        fix.safety = "safe";
        fix.replacementText = replacement;
        fix.offset = static_cast<int>(beginOffset);
        fix.length = static_cast<int>(totalLength);
        finding.fixes.push_back(fix);

        findings.push_back(finding);
    }

  private:
    static bool isSizeCall(const clang::Expr *expr) {
        if (expr == nullptr) {
            return false;
        }
        expr = expr->IgnoreParenImpCasts();
        if (const auto *call = llvm::dyn_cast<clang::CXXMemberCallExpr>(expr)) {
            if (const auto *method = call->getMethodDecl()) {
                auto name = method->getDeclName();
                return name.isIdentifier() && method->getName() == "size";
            }
        }
        return false;
    }

    /// Return true if the comparison should be replaced by `!empty()`,
    /// false for `empty()`, or nullopt if the comparison is trivially
    /// true/false and shouldn't be auto-fixed.
    static std::optional<bool>
    classifyComparison(clang::BinaryOperator::Opcode opcode, bool sizeIsLhs) {
        using Opc = clang::BinaryOperatorKind;
        // Canonicalise: if size() is on the RHS, flip the comparison.
        if (!sizeIsLhs) {
            switch (opcode) {
            case Opc::BO_GT:
                opcode = Opc::BO_LT;
                break;
            case Opc::BO_LT:
                opcode = Opc::BO_GT;
                break;
            case Opc::BO_GE:
                opcode = Opc::BO_LE;
                break;
            case Opc::BO_LE:
                opcode = Opc::BO_GE;
                break;
            default:
                break;
            }
        }

        switch (opcode) {
        case Opc::BO_EQ: // size() == 0
        case Opc::BO_LE: // size() <= 0  (effectively == 0 for unsigned)
            return false; // → empty()
        case Opc::BO_NE: // size() != 0
        case Opc::BO_GT: // size() > 0
            return true; // → !empty()
        case Opc::BO_GE: // size() >= 0 — always true; don't fix
        case Opc::BO_LT: // size() < 0  — always false; don't fix
        default:
            return std::nullopt;
        }
    }
};
} // namespace astharbor
