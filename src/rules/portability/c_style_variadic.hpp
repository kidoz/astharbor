#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {

/// Detects C-style variadic function definitions (`void f(int, ...)`).
/// Variadic functions bypass all type checking on the trailing
/// arguments, making them a frequent source of type-confusion bugs
/// and a barrier to safe refactoring. CERT DCL50-CPP recommends
/// variadic templates or `std::initializer_list` as the replacement.
class PortabilityCStyleVariadicRule : public Rule {
  public:
    std::string id() const override { return "portability/c-style-variadic"; }
    std::string title() const override { return "C-style variadic function"; }
    std::string category() const override { return "portability"; }
    std::string summary() const override {
        return "C-style variadic function definition — use variadic templates "
               "or std::initializer_list for type safety.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            functionDecl(isVariadic(), isDefinition(), unless(isExternC())).bind("variadic_func"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Func = Result.Nodes.getNodeAs<clang::FunctionDecl>("variadic_func");
        if (Func == nullptr || Result.SourceManager == nullptr) {
            return;
        }
        if (isInSystemHeader(Func->getLocation(), *Result.SourceManager)) {
            return;
        }
        emitFinding(Func->getLocation(), *Result.SourceManager,
                    "'" + Func->getNameAsString() +
                        "' is a C-style variadic function — use variadic "
                        "templates or std::initializer_list for type safety");
    }
};

} // namespace astharbor
