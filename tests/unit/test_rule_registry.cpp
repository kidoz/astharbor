#include <gtest/gtest.h>
#include "astharbor/rule_registry.hpp"

TEST(RuleRegistryTest, HasBuiltinRules) {
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
            EXPECT_EQ(r->category(), "modernize");
            EXPECT_EQ(r->defaultSeverity(), "warning");
        } else if (r->id() == "bugprone/assignment-in-condition") {
            foundAssignmentInCondition = true;
            EXPECT_EQ(r->category(), "bugprone");
            EXPECT_EQ(r->defaultSeverity(), "warning");
        } else if (r->id() == "bugprone/suspicious-semicolon") {
            foundSuspiciousSemicolon = true;
            EXPECT_EQ(r->category(), "bugprone");
            EXPECT_EQ(r->defaultSeverity(), "warning");
        } else if (r->id() == "bugprone/unsafe-memory-operation") {
            foundUnsafeMemoryOperation = true;
            EXPECT_EQ(r->category(), "bugprone");
            EXPECT_EQ(r->defaultSeverity(), "error");
        }
    }
    EXPECT_TRUE(foundNullptr);
    EXPECT_TRUE(foundAssignmentInCondition);
    EXPECT_TRUE(foundSuspiciousSemicolon);
    EXPECT_TRUE(foundUnsafeMemoryOperation);
    EXPECT_GE(rules.size(), 10u);
}
