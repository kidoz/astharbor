#pragma once

#include "astharbor/rule.hpp"

namespace astharbor {
class BugproneUnsafeMemoryOperationRule : public Rule {
  public:
    std::string id() const override { return "bugprone/unsafe-memory-operation"; }
    std::string title() const override { return "Unsafe memory operation"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "Detects memset/memcpy/memmove calls on non-trivially-copyable objects.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;

        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName("memset", "::memset", "std::memset", "memcpy",
                                                   "::memcpy", "std::memcpy", "memmove",
                                                   "::memmove", "std::memmove"))))
                .bind("memory_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("memory_call");
        if (Call == nullptr || Result.SourceManager == nullptr || Result.Context == nullptr) {
            return;
        }

        const auto *Callee = Call->getDirectCallee();
        if (Callee == nullptr) {
            return;
        }

        const std::string FunctionName = Callee->getQualifiedNameAsString();
        const bool IsMemset = FunctionName == "memset" || FunctionName == "::memset" ||
                              FunctionName == "std::memset";
        const bool IsMemcpyLike = FunctionName == "memcpy" || FunctionName == "::memcpy" ||
                                  FunctionName == "std::memcpy" || FunctionName == "memmove" ||
                                  FunctionName == "::memmove" || FunctionName == "std::memmove";

        bool Unsafe = false;
        if (IsMemset && Call->getNumArgs() >= 1) {
            Unsafe = hasNonTrivialPointee(Call->getArg(0), *Result.Context);
        } else if (IsMemcpyLike && Call->getNumArgs() >= 2) {
            Unsafe = hasNonTrivialPointee(Call->getArg(0), *Result.Context) ||
                     hasNonTrivialPointee(Call->getArg(1), *Result.Context);
        }

        if (!Unsafe) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        const auto Location = Call->getExprLoc();

        Finding finding;
        finding.ruleId = id();
        finding.message = FunctionName +
                    " operates on a non-trivially-copyable type and can bypass object semantics";
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
    static bool hasNonTrivialPointee(const clang::Expr *Expression, const clang::ASTContext &Context) {
        if (Expression == nullptr) {
            return false;
        }

        const clang::QualType Type = Expression->IgnoreParenImpCasts()->getType();
        if (!Type->isPointerType()) {
            return false;
        }

        const clang::QualType Pointee = Type->getPointeeType();
        if (Pointee.isNull() || Pointee->isVoidType() || Pointee->isIncompleteType()) {
            return false;
        }

        return !Pointee.isTriviallyCopyableType(Context);
    }
};
} // namespace astharbor
