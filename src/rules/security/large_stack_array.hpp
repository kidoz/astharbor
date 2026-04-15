#pragma once
#include "astharbor/rule.hpp"
#include <clang/AST/Type.h>

namespace astharbor {
class SecurityLargeStackArrayRule : public Rule {
  public:
    std::string id() const override { return "security/large-stack-array"; }
    std::string title() const override { return "Large stack array"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects local fixed-size arrays that exceed a size threshold, risking stack "
               "overflow.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            varDecl(hasLocalStorage(), hasType(constantArrayType())).bind("stack_array"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *VarDeclaration = Result.Nodes.getNodeAs<clang::VarDecl>("stack_array");
        if (VarDeclaration == nullptr || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        if (isInSystemHeader(VarDeclaration->getLocation(), *Result.SourceManager)) {
            return;
        }

        const auto *ArrayType = Result.Context->getAsConstantArrayType(VarDeclaration->getType());
        if (ArrayType == nullptr) {
            return;
        }
        if (ArrayType->getElementType().isNull() ||
            ArrayType->getElementType()->isIncompleteType()) {
            return;
        }

        uint64_t NumElements = ArrayType->getSize().getZExtValue();
        clang::CharUnits ElementSize =
            Result.Context->getTypeSizeInChars(ArrayType->getElementType());
        uint64_t TotalBytes = NumElements * ElementSize.getQuantity();

        if (TotalBytes < StackSizeThreshold) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;

        Finding finding;
        finding.ruleId = id();
        finding.message = "Local array of " + std::to_string(TotalBytes) +
                          " bytes on the stack risks stack overflow (CWE-121) — consider heap "
                          "allocation or std::vector";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(VarDeclaration->getLocation()).str();
        finding.line = sourceManager.getSpellingLineNumber(VarDeclaration->getLocation());
        finding.column = sourceManager.getSpellingColumnNumber(VarDeclaration->getLocation());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }

  private:
    static constexpr uint64_t StackSizeThreshold = 4096;
};
} // namespace astharbor
