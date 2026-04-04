#pragma once
#include "astharbor/rule_registry.hpp"
#include "astharbor/emitter.hpp"
#include <clang/Tooling/Tooling.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>

namespace astharbor {

inline std::string generateRunId() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now.time_since_epoch())
                         .count();
    std::ostringstream stream;
    stream << "run-" << std::hex << timestamp;
    return stream.str();
}

class Analyzer {
  public:
    Analyzer(const RuleRegistry &registry, IEmitter &emitter);
    int run(clang::tooling::ClangTool &tool, const std::string &runId = "");

  private:
    const RuleRegistry &registry;
    IEmitter &emitter;
};

} // namespace astharbor
