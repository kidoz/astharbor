#pragma once

#include "astharbor/rule.hpp"

#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <llvm/Support/Casting.h>

namespace astharbor {
class BugproneAssignmentInConditionRule : public Rule {
  public:
    std::string id() const override { return "bugprone/assignment-in-condition"; }
    std::string title() const override { return "Assignment in condition"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Detects assignments used directly inside conditional expressions.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(ifStmt(hasCondition(expr().bind("condition"))), this);
        Finder.addMatcher(whileStmt(hasCondition(expr().bind("condition"))), this);
        Finder.addMatcher(doStmt(hasCondition(expr().bind("condition"))), this);
        Finder.addMatcher(forStmt(hasCondition(expr().bind("condition"))), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Condition = Result.Nodes.getNodeAs<clang::Expr>("condition");
        if (Condition == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        if (isInSystemHeader(Condition->getBeginLoc(), *Result.SourceManager)) {
            return;
        }

        const auto *Assignment = findAssignmentExpr(Condition->IgnoreParenImpCasts());
        if (Assignment == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        const auto Location = Assignment->getExprLoc();

        Finding finding;
        finding.ruleId = id();
        finding.message = "Assignment used inside a condition; this is often a mistaken '=='";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(Location).str();
        finding.line = sourceManager.getSpellingLineNumber(Location);
        finding.column = sourceManager.getSpellingColumnNumber(Location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }

  private:
    static const clang::Expr *findAssignmentExpr(const clang::Stmt *Statement) {
        if (Statement == nullptr) {
            return nullptr;
        }

        if (const auto *Expression = llvm::dyn_cast<clang::Expr>(Statement)) {
            const auto *Spelled = Expression->IgnoreParenImpCasts();

            if (const auto *Binary = llvm::dyn_cast<clang::BinaryOperator>(Spelled);
                Binary != nullptr && Binary->isAssignmentOp()) {
                return Binary;
            }

            if (const auto *OperatorCall = llvm::dyn_cast<clang::CXXOperatorCallExpr>(Spelled);
                OperatorCall != nullptr && OperatorCall->getOperator() == clang::OO_Equal) {
                return OperatorCall;
            }
        }

        for (const auto *Child : Statement->children()) {
            if (const auto *Found = findAssignmentExpr(Child)) {
                return Found;
            }
        }

        return nullptr;
    }
};
} // namespace astharbor
