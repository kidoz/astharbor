#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects variable-length arrays in C++ code. VLAs are a C99 feature and
/// are not standard C++; their presence here compiles only by extension
/// and is non-portable between toolchains and language modes.
class PortabilityVlaInCxxRule : public Rule {
  public:
    std::string id() const override { return "portability/vla-in-cxx"; }
    std::string title() const override { return "Variable-length array in C++"; }
    std::string category() const override { return "portability"; }
    std::string summary() const override {
        return "Variable-length arrays are not standard C++ and are non-portable between "
               "toolchains and language modes.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(varDecl(hasType(variableArrayType())).bind("vla_decl"), this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *VarDeclNode = Result.Nodes.getNodeAs<clang::VarDecl>("vla_decl");
        if (VarDeclNode == nullptr || Result.SourceManager == nullptr ||
            Result.Context == nullptr) {
            return;
        }
        // Only flag in C++ mode — VLAs are valid in C99+.
        if (!Result.Context->getLangOpts().CPlusPlus) {
            return;
        }
        if (isInSystemHeader(VarDeclNode->getLocation(), *Result.SourceManager)) {
            return;
        }

        Finding finding;
        finding.ruleId = id();
        finding.message = "Variable-length array '" + VarDeclNode->getNameAsString() +
                          "' is not standard C++; prefer std::vector or a fixed-size array";
        finding.severity = defaultSeverity();
        finding.category = category();

        auto &sourceManager = *Result.SourceManager;
        auto location = sourceManager.getExpansionLoc(VarDeclNode->getLocation());
        finding.file = sourceManager.getFilename(location).str();
        finding.line = sourceManager.getSpellingLineNumber(location);
        finding.column = sourceManager.getSpellingColumnNumber(location);

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};

} // namespace astharbor
