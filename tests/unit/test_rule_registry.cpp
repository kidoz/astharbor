#include <catch2/catch_test_macros.hpp>
#include "astharbor/rule_registry.hpp"

TEST_CASE("RuleRegistryTest.HasBuiltinRules") {
    astharbor::RuleRegistry registry;
    astharbor::registerBuiltinRules(registry);
    const auto &rules = registry.getRules();

    bool foundNullptr = false;
    bool foundAssignmentInCondition = false;
    bool foundSuspiciousSemicolon = false;
    bool foundUnsafeMemoryOperation = false;
    for (const auto &r : rules) {
        if (r->id() == "modernize/use-nullptr") {
            foundNullptr = true;
            CHECK(r->category() == "modernize");
            CHECK(r->defaultSeverity() == "warning");
        } else if (r->id() == "bugprone/assignment-in-condition") {
            foundAssignmentInCondition = true;
            CHECK(r->category() == "bugprone");
            CHECK(r->defaultSeverity() == "warning");
        } else if (r->id() == "bugprone/suspicious-semicolon") {
            foundSuspiciousSemicolon = true;
            CHECK(r->category() == "bugprone");
            CHECK(r->defaultSeverity() == "warning");
        } else if (r->id() == "bugprone/unsafe-memory-operation") {
            foundUnsafeMemoryOperation = true;
            CHECK(r->category() == "bugprone");
            CHECK(r->defaultSeverity() == "error");
        }
    }
    CHECK(foundNullptr);
    CHECK(foundAssignmentInCondition);
    CHECK(foundSuspiciousSemicolon);
    CHECK(foundUnsafeMemoryOperation);
    CHECK(rules.size() >= 10u);
}
