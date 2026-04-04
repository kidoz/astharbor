#pragma once
#include "rule.hpp"
#include <memory>
#include <vector>

namespace astharbor {
class RuleRegistry {
  public:
    void registerRule(std::unique_ptr<Rule> rule) { rules.push_back(std::move(rule)); }
    const std::vector<std::unique_ptr<Rule>> &getRules() const { return rules; }

  private:
    std::vector<std::unique_ptr<Rule>> rules;
};

void registerBuiltinRules(RuleRegistry &registry);

} // namespace astharbor
