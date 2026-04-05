#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects raw `new` and `delete` expressions that indicate manual ownership
/// management. Modern C++ prefers smart pointers (`std::unique_ptr`,
/// `std::shared_ptr`, `std::make_unique`, `std::make_shared`) or container
/// types for clearer ownership and automatic cleanup.
class BestPracticeNoRawNewDeleteRule : public Rule {
  public:
    std::string id() const override { return "best-practice/no-raw-new-delete"; }
    std::string title() const override { return "Avoid raw new/delete"; }
    std::string category() const override { return "best-practice"; }
    std::string summary() const override {
        return "Raw new/delete expressions signal manual ownership; prefer smart pointers "
               "(unique_ptr/shared_ptr) or containers.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(cxxNewExpr().bind("new_expr"), this);
        Finder.addMatcher(cxxDeleteExpr().bind("delete_expr"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        if (Result.SourceManager == nullptr) {
            return;
        }
        if (const auto *NewExpr = Result.Nodes.getNodeAs<clang::CXXNewExpr>("new_expr")) {
            // Skip placement new — it is legitimately used with custom allocators.
            if (NewExpr->getNumPlacementArgs() > 0) {
                return;
            }
            if (isInSystemHeader(NewExpr->getBeginLoc(), *Result.SourceManager)) {
                return;
            }
            emit(*NewExpr, *Result.SourceManager, "Raw 'new' expression — prefer "
                                                   "std::make_unique/std::make_shared or a "
                                                   "container type");
            return;
        }
        if (const auto *DeleteExpr = Result.Nodes.getNodeAs<clang::CXXDeleteExpr>("delete_expr")) {
            if (isInSystemHeader(DeleteExpr->getBeginLoc(), *Result.SourceManager)) {
                return;
            }
            emit(*DeleteExpr, *Result.SourceManager,
                 "Raw 'delete' expression — manual ownership; prefer smart pointers");
            return;
        }
    }

  private:
    void emit(const clang::Expr &expr, const clang::SourceManager &sourceManager,
              const std::string &message) {
        Finding finding;
        finding.ruleId = id();
        finding.message = message;
        finding.severity = defaultSeverity();
        finding.category = category();
        auto location = sourceManager.getExpansionLoc(expr.getBeginLoc());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);
        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};

} // namespace astharbor
