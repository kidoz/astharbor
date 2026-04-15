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
        // Push the polymorphic-record check into the matcher so the AST
        // visitor short-circuits on non-polymorphic pointer arithmetic
        // instead of letting every `+`, `-`, `++`, `--`, and `[]` fire the
        // run() callback.
        auto polyRecord = cxxRecordDecl(hasMethod(isVirtual())).bind("poly_record");
        auto polyPointerType = pointerType(pointee(hasDeclaration(polyRecord)));

        Finder.addMatcher(
            unaryOperator(hasAnyOperatorName("++", "--"), hasUnaryOperand(hasType(polyPointerType)))
                .bind("unary_ptr_arith"),
            this);
        Finder.addMatcher(binaryOperator(hasAnyOperatorName("+", "-", "+=", "-="),
                                         hasEitherOperand(hasType(polyPointerType)))
                              .bind("binary_ptr_arith"),
                          this);
        Finder.addMatcher(
            arraySubscriptExpr(hasBase(ignoringParenImpCasts(hasType(polyPointerType))))
                .bind("subscript_ptr_arith"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const clang::SourceLocation reportLoc = getReportLocation(Result);
        if (reportLoc.isInvalid()) {
            return;
        }
        const auto *recordDecl = Result.Nodes.getNodeAs<clang::CXXRecordDecl>("poly_record");
        std::string recordName = recordDecl != nullptr ? recordDecl->getNameAsString() : "?";

        emitFinding(reportLoc, *Result.SourceManager,
                    "Pointer arithmetic on polymorphic type '" + recordName +
                        "' — if the dynamic type is a derived class, the arithmetic is "
                        "undefined");
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
