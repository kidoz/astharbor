#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/RecursiveASTVisitor.h>

namespace astharbor {

/// Detects reads of a local scalar variable before any write. Overlaps
/// somewhat with Clang's own `-Wuninitialized`, but runs inside the
/// ASTHarbor pipeline so findings flow through SARIF, fix command
/// plumbing, and the MCP server uniformly.
///
/// Implementation: when we see a `VarDecl` without an initializer that
/// has scalar type (integer / float / pointer), walk the enclosing
/// function's body and report the first read that occurs before any
/// assignment. Like the other Tier 2 rules this uses source-location
/// ordering rather than full `clang::CFG` analysis; branches where the
/// variable is initialized in one arm but read in another may produce
/// false positives.
class UbUninitializedLocalRule : public Rule {
  public:
    std::string id() const override { return "ub/uninitialized-local"; }
    std::string title() const override { return "Uninitialized local scalar"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Read of a local scalar variable before any write — reading an indeterminate "
               "value is undefined behavior.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            varDecl(hasLocalStorage(), unless(hasInitializer(expr())),
                    hasType(qualType(anyOf(isInteger(), realFloatingPointType(),
                                            pointerType()))),
                    hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("uninit_var"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *VarDeclNode = Result.Nodes.getNodeAs<clang::VarDecl>("uninit_var");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (VarDeclNode == nullptr || Func == nullptr || !Func->hasBody() ||
            Result.SourceManager == nullptr) {
            return;
        }
        // Skip static and thread-local locals — they are zero-initialized.
        if (VarDeclNode->isStaticLocal() || VarDeclNode->getTLSKind() !=
                                                 clang::VarDecl::TLS_None) {
            return;
        }
        // Skip records and arrays — record types may have default constructors
        // and array initialization is handled elsewhere.
        clang::QualType type = VarDeclNode->getType();
        if (type->isRecordType() || type->isArrayType()) {
            return;
        }
        if (isInSystemHeader(VarDeclNode->getLocation(), *Result.SourceManager)) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        clang::SourceLocation declEnd =
            sourceManager.getExpansionLoc(VarDeclNode->getEndLoc());

        Visitor visitor(VarDeclNode, declEnd, sourceManager);
        visitor.TraverseStmt(Func->getBody());

        if (visitor.readLocation.isInvalid()) {
            return;
        }

        emitFinding(visitor.readLocation, sourceManager,
                    "Local '" + VarDeclNode->getNameAsString() +
                        "' is read before any write — reading an indeterminate value is "
                        "undefined behavior");
    }

  private:
    class Visitor : public clang::RecursiveASTVisitor<Visitor> {
      public:
        Visitor(const clang::VarDecl *var, clang::SourceLocation declEnd,
                const clang::SourceManager &sourceManager)
            : targetVar(var), declarationEnd(declEnd), sm(sourceManager) {}

        // Assignments to the variable count as its first write.
        bool TraverseBinaryOperator(clang::BinaryOperator *op) {
            if (op->isAssignmentOp()) {
                auto *lhs = op->getLHS()->IgnoreParenImpCasts();
                if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(lhs);
                    ref != nullptr && ref->getDecl() == targetVar) {
                    TraverseStmt(op->getRHS());
                    auto loc = sm.getExpansionLoc(op->getExprLoc());
                    if (sm.isBeforeInTranslationUnit(declarationEnd, loc)) {
                        written = true;
                    }
                    return true;
                }
            }
            return clang::RecursiveASTVisitor<Visitor>::TraverseBinaryOperator(op);
        }

        // Address-of operations count as writes from the rule's perspective:
        // once a caller has the address, we can't reason about reads.
        bool VisitUnaryOperator(clang::UnaryOperator *op) {
            if (op->getOpcode() == clang::UO_AddrOf) {
                if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(
                        op->getSubExpr()->IgnoreParenImpCasts());
                    ref != nullptr && ref->getDecl() == targetVar) {
                    written = true;
                }
            }
            return true;
        }

        bool VisitDeclRefExpr(clang::DeclRefExpr *ref) {
            if (readLocation.isValid()) {
                return true;
            }
            if (ref->getDecl() != targetVar) {
                return true;
            }
            auto loc = sm.getExpansionLoc(ref->getBeginLoc());
            if (!sm.isBeforeInTranslationUnit(declarationEnd, loc)) {
                return true;
            }
            if (written) {
                return true;
            }
            readLocation = loc;
            return true;
        }

        clang::SourceLocation readLocation;

      private:
        const clang::VarDecl *targetVar;
        clang::SourceLocation declarationEnd;
        const clang::SourceManager &sm;
        bool written = false;
    };
};

} // namespace astharbor
