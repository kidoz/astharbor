#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Expr.h>
#include <clang/AST/OperationKinds.h>

namespace astharbor {

/// Detects casts between pointer and integer types where the integer
/// is narrower than the pointer (CERT INT36-C / MISRA 11.6 / CWE-587):
///
///     void *p = ...;
///     int i = (int)p;       // truncation on LP64
///     void *q = (void*)i;   // expansion loses upper bits
///
/// Both C-style and reinterpret_cast forms are matched.
class PortabilityPointerIntegerCastRule : public Rule {
  public:
    std::string id() const override { return "portability/pointer-integer-cast"; }
    std::string title() const override { return "Pointer/integer cast truncation"; }
    std::string category() const override { return "portability"; }
    std::string summary() const override {
        return "Cast between pointer and integer of different width — truncates "
               "or zero-extends, producing a non-portable result.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        // C-style cast: (int)ptr or (void*)i
        Finder.addMatcher(
            cStyleCastExpr(anyOf(
                hasCastKind(clang::CK_PointerToIntegral),
                hasCastKind(clang::CK_IntegralToPointer)))
                .bind("cast"),
            this);
        // reinterpret_cast<int>(ptr) or reinterpret_cast<void*>(i)
        Finder.addMatcher(
            cxxReinterpretCastExpr(anyOf(
                hasCastKind(clang::CK_PointerToIntegral),
                hasCastKind(clang::CK_IntegralToPointer)))
                .bind("cast"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Cast = Result.Nodes.getNodeAs<clang::ExplicitCastExpr>("cast");
        if (Cast == nullptr || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(Cast->getExprLoc(), *Result.SourceManager)) {
            return;
        }
        // Identify the pointer and integer types.
        clang::QualType destType = Cast->getType();
        clang::QualType srcType = Cast->getSubExpr()->getType();
        if (destType.isNull() || srcType.isNull()) {
            return;
        }
        const clang::QualType ptrType =
            destType->isPointerType() ? destType : srcType;
        const clang::QualType intType =
            destType->isIntegerType() ? destType : srcType;
        if (!ptrType->isPointerType() || !intType->isIntegerType()) {
            return;
        }
        // Allow casts to/from intptr_t / uintptr_t-sized integers.
        const uint64_t ptrWidth =
            Result.Context->getTypeSize(Result.Context->VoidPtrTy);
        const uint64_t intWidth = Result.Context->getTypeSize(intType);
        if (intWidth >= ptrWidth) {
            return;
        }
        emitFinding(Cast->getExprLoc(), *Result.SourceManager,
                    "Cast between pointer and " + std::to_string(intWidth) +
                        "-bit integer truncates on this platform (pointer is " +
                        std::to_string(ptrWidth) + " bits)");
    }
};

} // namespace astharbor
