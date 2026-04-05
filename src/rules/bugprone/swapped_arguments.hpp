#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <string>

namespace astharbor {

/// Detects call sites where the argument variable names cross-match the
/// callee's parameter names — a strong signal that the programmer
/// passed the arguments in the wrong order. Classic example:
///
///     void copy(char *dst, const char *src, size_t n);
///     void caller() {
///         char dst[32], src[32];
///         copy(src, dst, 32);   // swapped
///     }
///
/// The heuristic:
///   * Each argument must be a plain `DeclRefExpr` to a local variable
///     (literals, expressions, and member accesses are skipped).
///   * Each variable name and each parameter name must have length ≥ 2
///     (single-letter names like `a`, `x`, `i` recur with no semantic
///     weight and would generate too many false positives).
///   * A pair of argument positions (i, j) is flagged when the variable
///     at i has the same name as the parameter at j AND the variable
///     at j has the same name as the parameter at i.
///
/// Operator calls (`CXXOperatorCallExpr`) are excluded because their
/// argument list is offset by the implicit `this` and doesn't line up
/// with the callee's parameter list in the same way plain calls do.
class BugproneSwappedArgumentsRule : public Rule {
  public:
    std::string id() const override { return "bugprone/swapped-arguments"; }
    std::string title() const override { return "Swapped call arguments"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Argument variable names cross-match the callee's parameter names — "
               "likely a swap bug.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(unless(cxxOperatorCallExpr()),
                     callee(functionDecl().bind("callee_decl")))
                .bind("call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("call");
        const auto *Callee = Result.Nodes.getNodeAs<clang::FunctionDecl>("callee_decl");
        if (Call == nullptr || Callee == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        const auto params = Callee->parameters();
        const unsigned numFixed =
            std::min<unsigned>(Call->getNumArgs(), params.size());
        if (numFixed < 2) {
            return;
        }

        // Collect (index, name) pairs for arguments that are direct
        // references to a named variable of length >= 2.
        struct ArgInfo {
            unsigned index;
            llvm::StringRef name;
        };
        llvm::SmallVector<ArgInfo, 8> argNames;
        for (unsigned index = 0; index < numFixed; ++index) {
            const clang::Expr *arg = Call->getArg(index)->IgnoreParenImpCasts();
            const auto *ref = llvm::dyn_cast<clang::DeclRefExpr>(arg);
            if (ref == nullptr) {
                continue;
            }
            const auto *varDecl = llvm::dyn_cast<clang::VarDecl>(ref->getDecl());
            if (varDecl == nullptr) {
                continue;
            }
            llvm::StringRef name = varDecl->getName();
            if (name.size() < 2) {
                continue;
            }
            argNames.push_back({index, name});
        }
        if (argNames.size() < 2) {
            return;
        }

        for (size_t outer = 0; outer < argNames.size(); ++outer) {
            for (size_t inner = outer + 1; inner < argNames.size(); ++inner) {
                const auto &lhs = argNames[outer];
                const auto &rhs = argNames[inner];
                if (lhs.name == rhs.name) {
                    continue;
                }
                llvm::StringRef paramLhs = params[lhs.index]->getName();
                llvm::StringRef paramRhs = params[rhs.index]->getName();
                if (paramLhs.size() < 2 || paramRhs.size() < 2) {
                    continue;
                }
                // A match requires each argument's variable name to be
                // identical to the OTHER position's parameter name.
                if (lhs.name == paramRhs && rhs.name == paramLhs) {
                    emitFinding(
                        Call->getArg(lhs.index)->getBeginLoc(),
                        *Result.SourceManager,
                        "Arguments '" + lhs.name.str() + "' and '" + rhs.name.str() +
                            "' appear swapped: they match the parameter names '" +
                            paramRhs.str() + "' and '" + paramLhs.str() +
                            "' of the opposite position");
                    return; // one finding per call site
                }
            }
        }
    }
};

} // namespace astharbor
