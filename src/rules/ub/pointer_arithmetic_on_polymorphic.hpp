#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects pointer arithmetic (++, --, +, -, +=, -=, []) on a pointer whose
/// pointee type is polymorphic. Pointer arithmetic is only defined when the
/// pointer points to an element of an array of that exact type; for
/// polymorphic types, derived objects may have different sizes making the
/// arithmetic compute wrong addresses. See [expr.add]/4.
class UbPointerArithmeticOnPolymorphicRule : public Rule {
  public:
    std::string id() const override { return "ub/pointer-arithmetic-on-polymorphic"; }
    std::string title() const override { return "Pointer arithmetic on polymorphic type"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Pointer arithmetic on a polymorphic base pointer — undefined behavior when the "
               "dynamic type differs in size.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            unaryOperator(hasAnyOperatorName("++", "--"),
                          hasUnaryOperand(expr(hasType(pointerType())).bind("ptr_operand")))
                .bind("unary_ptr_arith"),
            this);
        Finder.addMatcher(
            binaryOperator(hasAnyOperatorName("+", "-", "+=", "-="),
                           hasEitherOperand(expr(hasType(pointerType())).bind("ptr_operand")))
                .bind("binary_ptr_arith"),
            this);
        Finder.addMatcher(
            arraySubscriptExpr(hasBase(ignoringParenImpCasts(
                                   expr(hasType(pointerType())).bind("ptr_operand"))))
                .bind("subscript_ptr_arith"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Operand = Result.Nodes.getNodeAs<clang::Expr>("ptr_operand");
        if (Operand == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        const clang::SourceLocation reportLoc = getReportLocation(Result);
        if (reportLoc.isInvalid() || isInSystemHeader(reportLoc, *Result.SourceManager)) {
            return;
        }

        clang::QualType operandType = Operand->getType();
        if (!operandType->isPointerType()) {
            return;
        }
        clang::QualType pointeeType = operandType->getPointeeType();
        const clang::CXXRecordDecl *recordDecl = pointeeType->getAsCXXRecordDecl();
        if (recordDecl == nullptr || !recordDecl->hasDefinition()) {
            return;
        }
        if (!recordDecl->isPolymorphic()) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.message =
            "Pointer arithmetic on polymorphic type '" + recordDecl->getNameAsString() +
            "' — if the dynamic type is a derived class, the arithmetic is undefined";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(reportLoc);
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }

  private:
    static clang::SourceLocation
    getReportLocation(const clang::ast_matchers::MatchFinder::MatchResult &Result) {
        if (const auto *Node = Result.Nodes.getNodeAs<clang::UnaryOperator>("unary_ptr_arith")) {
            return Node->getExprLoc();
        }
        if (const auto *Node = Result.Nodes.getNodeAs<clang::BinaryOperator>("binary_ptr_arith")) {
            return Node->getExprLoc();
        }
        if (const auto *Node =
                Result.Nodes.getNodeAs<clang::ArraySubscriptExpr>("subscript_ptr_arith")) {
            return Node->getExprLoc();
        }
        return clang::SourceLocation{};
    }
};

} // namespace astharbor
