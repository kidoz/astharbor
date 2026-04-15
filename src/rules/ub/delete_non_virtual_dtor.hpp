#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/DeclCXX.h>

namespace astharbor {

/// Detects `delete` expressions on a pointer to a class that has virtual
/// methods but lacks a virtual destructor. If the actual dynamic type is a
/// derived class, deletion through the base pointer is undefined behavior
/// per [expr.delete]/3.
class UbDeleteNonVirtualDtorRule : public Rule {
  public:
    std::string id() const override { return "ub/delete-non-virtual-dtor"; }
    std::string title() const override {
        return "Delete polymorphic object without virtual destructor";
    }
    std::string category() const override { return "ub"; }
    std::string summary() const override {
        return "Delete through base pointer without virtual destructor — undefined behavior "
               "for polymorphic types.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(cxxDeleteExpr().bind("delete_expr"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *DeleteExpr = Result.Nodes.getNodeAs<clang::CXXDeleteExpr>("delete_expr");
        if (DeleteExpr == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(DeleteExpr->getExprLoc(), *Result.SourceManager)) {
            return;
        }

        // Get the pointee type of the deleted expression
        clang::QualType argType = DeleteExpr->getArgument()->getType();
        if (!argType->isPointerType()) {
            return;
        }
        clang::QualType pointeeType = argType->getPointeeType();
        const clang::CXXRecordDecl *recordDecl = pointeeType->getAsCXXRecordDecl();
        if (recordDecl == nullptr || !recordDecl->hasDefinition()) {
            return;
        }

        // Only flag if the class is polymorphic (has virtual methods)
        if (!recordDecl->isPolymorphic()) {
            return;
        }

        // Find the destructor and check if it's virtual
        const clang::CXXDestructorDecl *destructor = recordDecl->getDestructor();
        if (destructor == nullptr || destructor->isVirtual()) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.message = "Deleting object of polymorphic class '" + recordDecl->getNameAsString() +
                          "' which lacks a virtual destructor — undefined behavior if the "
                          "dynamic type is a derived class";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(DeleteExpr->getExprLoc());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};

} // namespace astharbor
