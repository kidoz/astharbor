#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/ParentMapContext.h>

namespace astharbor {

class BugproneIgnoredReturnValueRule : public Rule {
  public:
    std::string id() const override { return "bugprone/ignored-return-value"; }
    std::string title() const override { return "Ignored important return value"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Return value of an error-reporting C/POSIX API is discarded.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(
                callee(functionDecl(hasAnyName(
                    "fread", "fwrite", "fgets", "scanf", "sscanf", "fscanf", "snprintf", "read",
                    "write", "strtol", "strtoul", "strtoll", "strtoull", "strtod", "pthread_create",
                    "pthread_join", "pthread_mutex_lock", "pthread_mutex_unlock", "fclose",
                    "::fread", "::fwrite", "::fgets", "::scanf", "::sscanf", "::fscanf",
                    "::snprintf", "::read", "::write", "::strtol", "::strtoul", "::strtoll",
                    "::strtoull", "::strtod", "::pthread_create", "::pthread_join",
                    "::pthread_mutex_lock", "::pthread_mutex_unlock", "::fclose"))))
                .bind("important_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("important_call");
        if (Call == nullptr || Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        if (isReturnValueUsed(*Call, *Result.Context)) {
            return;
        }
        const auto *Callee = Call->getDirectCallee();
        const std::string name = Callee != nullptr ? Callee->getNameAsString() : "call";
        emitFinding(Call->getExprLoc(), *Result.SourceManager,
                    "Return value of " + name +
                        "() is ignored — check it for errors or short reads/writes");
    }

  private:
    static bool isReturnValueUsed(const clang::CallExpr &Call, clang::ASTContext &Context) {
        auto parents = Context.getParents(Call);
        if (parents.empty()) {
            return false;
        }
        if (parents[0].get<clang::CompoundStmt>()) {
            return false;
        }
        return true;
    }
};

} // namespace astharbor
