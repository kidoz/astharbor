#include "astharbor/analyzer.hpp"
#include "astharbor/result.hpp"
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <cstdio>
#include <iostream>

namespace astharbor {

Analyzer::Analyzer(const RuleRegistry &registry, IEmitter &emitter)
    : registry(registry), emitter(emitter) {}

int Analyzer::run(clang::tooling::ClangTool &tool, const std::string &runId) {
    clang::ast_matchers::MatchFinder finder;
    for (const auto &rule : registry.getRules()) {
        rule->registerMatchers(finder);
    }

    int toolExitCode = tool.run(clang::tooling::newFrontendActionFactory(&finder).get());

    AnalysisResult analysisResult;
    analysisResult.runId = runId.empty() ? generateRunId() : runId;
    analysisResult.success = (toolExitCode == 0);
    for (const auto &rule : registry.getRules()) {
        auto ruleFindings = rule->getFindings();
        analysisResult.findings.insert(analysisResult.findings.end(),
                                       ruleFindings.begin(), ruleFindings.end());
    }
    // Assign stable sequential findingIds so downstream consumers (MCP, fix
    // --finding-id, SARIF correlation) can reference individual findings.
    for (size_t index = 0; index < analysisResult.findings.size(); ++index) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "finding-%04zu", index);
        analysisResult.findings[index].findingId = buffer;
    }

    emitter.emit(analysisResult, std::cout);

    if (toolExitCode != 0) {
        return 2;
    }
    return analysisResult.findings.empty() ? 0 : 1;
}

} // namespace astharbor
