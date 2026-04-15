#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"

namespace astharbor {

class ResourceFileHandleLeakRule : public Rule {
  public:
    std::string id() const override { return "resource/file-handle-leak"; }
    std::string title() const override { return "File descriptor or FILE* leak"; }
    std::string category() const override { return "resource"; }
    std::string summary() const override {
        return "A local FILE* or file descriptor opened by fopen/open/socket is not closed in the "
               "same function.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            varDecl(hasLocalStorage(),
                    hasInitializer(ignoringParenImpCasts(
                        callExpr(callee(functionDecl(
                                     hasAnyName("fopen", "::fopen", "std::fopen", "::std::fopen"))))
                            .bind("open_call"))),
                    hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                .bind("resource_var"),
            this);
        Finder.addMatcher(varDecl(hasLocalStorage(),
                                  hasInitializer(ignoringParenImpCasts(
                                      callExpr(callee(functionDecl(hasAnyName(
                                                   "open", "socket", "::open", "::socket"))))
                                          .bind("open_call"))),
                                  hasAncestor(functionDecl(isDefinition()).bind("enclosing_func")))
                              .bind("resource_var"),
                          this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *ResourceVar = Result.Nodes.getNodeAs<clang::VarDecl>("resource_var");
        const auto *OpenCall = Result.Nodes.getNodeAs<clang::CallExpr>("open_call");
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("enclosing_func");
        if (ResourceVar == nullptr || OpenCall == nullptr || Func == nullptr || !Func->hasBody() ||
            Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(ResourceVar->getLocation(), *Result.SourceManager)) {
            return;
        }
        const auto *Callee = OpenCall->getDirectCallee();
        const std::string openName = Callee != nullptr ? Callee->getNameAsString() : "open";
        const bool wantsFclose = openName == "fopen";
        if (containsClose(Func->getBody(), ResourceVar, wantsFclose)) {
            return;
        }
        emitFinding(ResourceVar->getLocation(), *Result.SourceManager,
                    "Resource '" + ResourceVar->getNameAsString() + "' opened by " + openName +
                        "() is not closed in this function");
    }

  private:
    static bool containsClose(const clang::Stmt *stmt, const clang::VarDecl *targetVar,
                              bool wantsFclose) {
        return cfg::findFirstDescendantIf(stmt, [targetVar, wantsFclose](const clang::Stmt *node) {
                   const auto *call = llvm::dyn_cast<clang::CallExpr>(node);
                   if (call == nullptr || call->getNumArgs() == 0) {
                       return false;
                   }
                   const auto *callee = call->getDirectCallee();
                   if (callee == nullptr) {
                       return false;
                   }
                   const std::string name = callee->getNameAsString();
                   const bool isClose = wantsFclose ? name == "fclose" : name == "close";
                   return isClose && cfg::isDirectRefTo(call->getArg(0), targetVar);
               }) != nullptr;
    }
};

} // namespace astharbor
