#pragma once

#include "astharbor/cfg_reachability.hpp"
#include "astharbor/finding.hpp"
#include "astharbor/rule.hpp"

#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Tooling/Tooling.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace astharbor::test {

struct RuleRunResult {
    bool success = false;
    std::vector<Finding> findings;
};

inline RuleRunResult runRuleOnCode(std::unique_ptr<Rule> rule, std::string code,
                                   std::vector<std::string> args = {"-std=c++23"},
                                   std::string fileName = "input.cpp") {
    clang::ast_matchers::MatchFinder finder;
    Rule *const rulePtr = rule.get();
    rulePtr->registerMatchers(finder);

    auto actionFactory = clang::tooling::newFrontendActionFactory(&finder);

    RuleRunResult result;
    result.success = clang::tooling::runToolOnCodeWithArgs(actionFactory->create(), std::move(code),
                                                           args, std::move(fileName),
                                                           "/opt/homebrew/opt/llvm/bin/clang++");
    result.findings = rulePtr->getFindings();
    // Drop per-function CFG cache entries before the ASTContext this
    // invocation owned goes away. Consecutive tests on the same thread
    // would otherwise risk use-after-free on stale `FunctionDecl*`
    // keys that happened to alias new pointers in the next context.
    cfg::clearCfgCache();
    return result;
}

} // namespace astharbor::test
