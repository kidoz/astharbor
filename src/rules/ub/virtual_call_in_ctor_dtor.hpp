#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/DeclCXX.h>
#include <clang/AST/ExprCXX.h>

namespace astharbor {

/// Detects virtual method calls on `this` inside a constructor or
/// destructor body. The derived-class override is NOT dispatched —
/// the object's dynamic type is still the base at ctor time and
/// already the base again at dtor time. This surprises most
/// programmers and is flagged by CERT OOP50-CPP.
class UbVirtualCallInCtorDtorRule : public Rule {
  public:
    std::string id() const override { return "ub/virtual-call-in-ctor-dtor"; }
    std::string title() const override { return "Virtual call in constructor or destructor"; }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Virtual method called on 'this' inside a ctor/dtor — the "
               "derived override is not dispatched.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // A virtual member call whose implicit object is `this`
        // (CXXThisExpr), inside a ctor or dtor body.
        auto virtualOnThis = cxxMemberCallExpr(callee(cxxMethodDecl(isVirtual())),
                                               on(ignoringParenImpCasts(cxxThisExpr())));
        Finder.addMatcher(virtualOnThis.bind("vcall"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("vcall");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        // Walk parents to check if we're inside a ctor or dtor.
        // The matcher doesn't use hasAncestor because ctor/dtor
        // bodies can contain lambdas — a virtual call inside a
        // lambda captured by a ctor is fine (the lambda may run
        // later when the object is fully constructed). We walk up
        // to the nearest function-like scope and check.
        if (!isInsideCtorOrDtor(*Result.Context, *Call)) {
            return;
        }
        const clang::CXXMethodDecl *method = Call->getMethodDecl();
        const std::string methodName = method != nullptr ? method->getNameAsString() : "<virtual>";
        emitFinding(Call->getExprLoc(), *Result.SourceManager,
                    "Virtual call to '" + methodName +
                        "()' inside a constructor or destructor — the derived "
                        "override will not be dispatched");
    }

  private:
    /// Walk parent chain to check whether `stmt` is directly inside
    /// a CXXConstructorDecl or CXXDestructorDecl body (not across a
    /// lambda boundary).
    static bool isInsideCtorOrDtor(clang::ASTContext &context, const clang::Stmt &stmt) {
        auto parents = context.getParents(stmt);
        while (!parents.empty()) {
            const auto &node = parents[0];
            if (node.get<clang::LambdaExpr>()) {
                return false; // lambda boundary — stop
            }
            if (const auto *decl = node.get<clang::Decl>()) {
                return llvm::isa<clang::CXXConstructorDecl>(decl) ||
                       llvm::isa<clang::CXXDestructorDecl>(decl);
            }
            parents = context.getParents(node);
        }
        return false;
    }
};

} // namespace astharbor
