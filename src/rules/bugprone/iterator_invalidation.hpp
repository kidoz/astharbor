#pragma once
#include "astharbor/cfg_reachability.hpp"
#include "astharbor/rule.hpp"

namespace astharbor {

class BugproneIteratorInvalidationRule : public Rule {
  public:
    std::string id() const override { return "bugprone/iterator-invalidation"; }
    std::string title() const override { return "Iterator invalidation"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Iterator from a local container is used after a visible mutating call that may "
               "invalidate it.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(functionDecl(isDefinition()).bind("function"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("function");
        if (Func == nullptr || !Func->hasBody() || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Func->getLocation(), *Result.SourceManager)) {
            return;
        }
        std::vector<IteratorBinding> iterators;
        collectIterators(Func->getBody(), iterators, *Result.SourceManager);
        if (iterators.empty()) {
            return;
        }
        std::vector<Mutation> mutations;
        collectMutations(Func->getBody(), mutations, *Result.SourceManager);
        if (mutations.empty()) {
            return;
        }
        for (const auto &binding : iterators) {
            for (const auto &mutation : mutations) {
                if (binding.container != mutation.container || binding.offset >= mutation.offset) {
                    continue;
                }
                if (auto useLoc = findIteratorUseAfter(Func->getBody(), binding.iterator,
                                                       mutation.offset, *Result.SourceManager)) {
                    emitFinding(*useLoc, *Result.SourceManager,
                                "Iterator '" + binding.iterator->getNameAsString() +
                                    "' is used after a call to '" + mutation.method +
                                    "' that may invalidate it");
                    return;
                }
            }
        }
    }

  private:
    struct IteratorBinding {
        const clang::VarDecl *iterator = nullptr;
        const clang::VarDecl *container = nullptr;
        unsigned offset = 0;
    };
    struct Mutation {
        const clang::VarDecl *container = nullptr;
        std::string method;
        unsigned offset = 0;
    };

    static const clang::VarDecl *objectVar(const clang::Expr *expr) {
        if (expr == nullptr) {
            return nullptr;
        }
        expr = expr->IgnoreParenImpCasts();
        if (const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(expr)) {
            return llvm::dyn_cast<clang::VarDecl>(ref->getDecl());
        }
        if (const auto *member = llvm::dyn_cast<clang::MemberExpr>(expr)) {
            return objectVar(member->getBase());
        }
        return nullptr;
    }

    static void collectIterators(const clang::Stmt *stmt, std::vector<IteratorBinding> &out,
                                 const clang::SourceManager &sourceManager) {
        cfg::findFirstDescendantIf(stmt, [&](const clang::Stmt *node) {
            const auto *declStmt = llvm::dyn_cast<clang::DeclStmt>(node);
            if (declStmt == nullptr) {
                return false;
            }
            for (const clang::Decl *decl : declStmt->decls()) {
                const auto *var = llvm::dyn_cast<clang::VarDecl>(decl);
                if (var == nullptr || var->getInit() == nullptr) {
                    continue;
                }
                const auto *call =
                    cfg::findFirstDescendant<clang::CXXMemberCallExpr>(var->getInit());
                if (call == nullptr || call->getMethodDecl() == nullptr) {
                    continue;
                }
                const std::string method = call->getMethodDecl()->getNameAsString();
                if (method != "begin" && method != "end" && method != "cbegin" &&
                    method != "cend") {
                    continue;
                }
                const clang::VarDecl *container = objectVar(call->getImplicitObjectArgument());
                if (container != nullptr) {
                    out.push_back(
                        {var, container, sourceManager.getFileOffset(var->getLocation())});
                }
            }
            return false;
        });
    }

    static void collectMutations(const clang::Stmt *stmt, std::vector<Mutation> &out,
                                 const clang::SourceManager &sourceManager) {
        cfg::findFirstDescendantIf(stmt, [&](const clang::Stmt *node) {
            const auto *call = llvm::dyn_cast<clang::CXXMemberCallExpr>(node);
            if (call == nullptr || call->getMethodDecl() == nullptr) {
                return false;
            }
            const std::string method = call->getMethodDecl()->getNameAsString();
            if (method != "push_back" && method != "emplace_back" && method != "erase" &&
                method != "clear" && method != "reserve" && method != "resize" &&
                method != "insert") {
                return false;
            }
            const clang::VarDecl *container = objectVar(call->getImplicitObjectArgument());
            if (container != nullptr) {
                out.push_back({container, method, sourceManager.getFileOffset(call->getExprLoc())});
            }
            return false;
        });
    }

    static std::optional<clang::SourceLocation>
    findIteratorUseAfter(const clang::Stmt *stmt, const clang::VarDecl *iterator,
                         unsigned mutationOffset, const clang::SourceManager &sourceManager) {
        const clang::Stmt *found = cfg::findFirstDescendantIf(stmt, [&](const clang::Stmt *node) {
            if (node->getBeginLoc().isInvalid() ||
                sourceManager.getFileOffset(node->getBeginLoc()) <= mutationOffset) {
                return false;
            }
            if (const auto *unary = llvm::dyn_cast<clang::UnaryOperator>(node);
                unary != nullptr && unary->getOpcode() == clang::UO_Deref &&
                cfg::isDirectRefTo(unary->getSubExpr(), iterator)) {
                return true;
            }
            if (const auto *op = llvm::dyn_cast<clang::CXXOperatorCallExpr>(node);
                op != nullptr && op->getOperator() == clang::OO_Star && op->getNumArgs() > 0 &&
                cfg::isDirectRefTo(op->getArg(0), iterator)) {
                return true;
            }
            if (const auto *member = llvm::dyn_cast<clang::MemberExpr>(node);
                member != nullptr && member->isArrow() &&
                cfg::isDirectRefTo(member->getBase(), iterator)) {
                return true;
            }
            return false;
        });
        if (found == nullptr) {
            return std::nullopt;
        }
        return found->getBeginLoc();
    }
};

} // namespace astharbor
