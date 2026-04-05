#pragma once
#include "astharbor/emitter.hpp"
#include "astharbor/rule_registry.hpp"

namespace astharbor {

/// SARIF 2.1.0 emitter. When constructed with a RuleRegistry pointer, the
/// emitter writes a full `tool.driver.rules` metadata list and associates
/// each result with its rule by index — enabling rich display in consumers
/// like GitHub code scanning.
class SarifEmitter : public IEmitter {
  public:
    SarifEmitter() = default;
    explicit SarifEmitter(const RuleRegistry *registry) : ruleRegistry(registry) {}
    void emit(const AnalysisResult &result, std::ostream &out) override;

  private:
    const RuleRegistry *ruleRegistry = nullptr;
};

} // namespace astharbor
