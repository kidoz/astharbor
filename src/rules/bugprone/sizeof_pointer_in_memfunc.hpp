#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>

namespace astharbor {

/// Detects memory-function calls whose size argument is `sizeof(ptr)`
/// where `ptr` is the same pointer variable passed as the buffer:
///
///     int *p = malloc(…);
///     memset(p, 0, sizeof(p));     // bug: clears 8 bytes, not the buffer
///     memcpy(dst, src, sizeof(dst)); // bug: copies 8 bytes, not the array
///
/// `sizeof(ptr)` yields the pointer's storage size (typically 4 or 8),
/// not the pointee's. The caller nearly always meant `sizeof(*ptr)`,
/// `sizeof(type)`, or a separately-tracked length. This is a classic
/// CVE shape — see CVE-2017-17740, CVE-2020-15861, and many others.
///
/// Decayed-array parameters (`void f(char buf[256]) { memset(buf, 0,
/// sizeof(buf)); }`) are caught: in the AST the parameter has pointer
/// type, so the matcher flags it. The safe form uses a separately
/// passed length.
class BugproneSizeofPointerInMemfuncRule : public Rule {
  public:
    std::string id() const override { return "bugprone/sizeof-pointer-in-memfunc"; }
    std::string title() const override { return "sizeof(ptr) passed as memfunc size"; }
    std::string category() const override { return "bugprone"; }
    std::string summary() const override {
        return "A memory function receives sizeof(ptr) for its length — this is the "
               "pointer's size, not the buffer's, and nearly always a bug.";
    }
    std::string defaultSeverity() const override { return "error"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // The canonical "mem*" family plus bzero / bcopy. strncpy /
        // strlcpy take a length too but don't clear/copy the whole
        // buffer the same way; leave those for a separate rule if
        // needed.
        auto memFunc = callee(functionDecl(hasAnyName(
            "memset", "memcpy", "memmove", "memcmp", "bzero", "bcopy")));
        // Match ANY variable as the buffer candidate; the real
        // pointer-vs-array decision happens in run(), which can
        // distinguish a ParmVarDecl whose declared type is an array
        // (decayed at the use site) from a local VarDecl with a
        // genuine array type.
        auto bufferVarRef = ignoringParenImpCasts(
            declRefExpr(to(varDecl().bind("buf_var"))));
        // A direct variable reference under the sizeof, after
        // stripping parens and implicit casts. `sizeof(*p)`,
        // `sizeof(obj.field)`, and `sizeof(Type)` do NOT match
        // because their operand is not a bare DeclRefExpr.
        auto sizeofSameVar = unaryExprOrTypeTraitExpr(
            ofKind(clang::UETT_SizeOf),
            has(ignoringParenImpCasts(declRefExpr(
                to(varDecl(equalsBoundNode("buf_var")))))));
        Finder.addMatcher(
            callExpr(memFunc,
                     hasAnyArgument(bufferVarRef),
                     hasAnyArgument(ignoringParenImpCasts(sizeofSameVar)))
                .bind("bad_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("bad_call");
        const auto *BufVar = Result.Nodes.getNodeAs<clang::VarDecl>("buf_var");
        if (Call == nullptr || BufVar == nullptr ||
            Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Call->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        // A local VarDecl with genuine array type is fine:
        // `sizeof(local_arr)` is the full array length. The bug shape
        // only arises when the buffer is a pointer at the use site —
        // either declared as a pointer, or a function parameter whose
        // declared array type decays to a pointer.
        const bool isParameter = llvm::isa<clang::ParmVarDecl>(BufVar);
        const clang::QualType bufType = BufVar->getType();
        if (!bufType->isPointerType() && !(isParameter && bufType->isArrayType())) {
            return;
        }
        const clang::FunctionDecl *callee = Call->getDirectCallee();
        const std::string calleeName =
            callee != nullptr ? callee->getNameAsString() : "mem*";
        emitFinding(Call->getExprLoc(), *Result.SourceManager,
                    calleeName + "(..., sizeof(" + BufVar->getNameAsString() +
                        ")) measures the pointer's size, not the buffer's — "
                        "pass the actual length or sizeof(*" +
                        BufVar->getNameAsString() + ")");
    }
};

} // namespace astharbor
