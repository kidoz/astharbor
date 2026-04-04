#include <gtest/gtest.h>

#include "../../src/rules/bugprone/assignment_in_condition.hpp"
#include "../../src/rules/bugprone/suspicious_semicolon.hpp"
#include "../../src/rules/bugprone/unsafe_memory_operation.hpp"
#include "rule_test_utils.hpp"

TEST(BugproneAssignmentInConditionRuleTest, DetectsAssignmentInsideIfCondition) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneAssignmentInConditionRule>(),
        R"cpp(
            int test(int lhs, int rhs) {
                if (lhs = rhs) {
                    return lhs;
                }
                return 0;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "bugprone/assignment-in-condition");
}

TEST(BugproneAssignmentInConditionRuleTest, IgnoresEqualityComparisons) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneAssignmentInConditionRule>(),
        R"cpp(
            int test(int lhs, int rhs) {
                if (lhs == rhs) {
                    return lhs;
                }
                return 0;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(BugproneSuspiciousSemicolonRuleTest, DetectsEmptyIfBody) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSuspiciousSemicolonRule>(),
        R"cpp(
            void test(bool flag) {
                if (flag);
                {
                    (void)flag;
                }
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "bugprone/suspicious-semicolon");
}

TEST(BugproneSuspiciousSemicolonRuleTest, IgnoresNonEmptyIfBody) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSuspiciousSemicolonRule>(),
        R"cpp(
            void test(bool flag) {
                if (flag) {
                    (void)flag;
                }
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(BugproneUnsafeMemoryOperationRuleTest, DetectsMemsetOnNonTrivialType) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneUnsafeMemoryOperationRule>(),
        R"cpp(
            extern "C" void *memset(void *, int, unsigned long);

            struct Widget {
                Widget();
                ~Widget();
                int value;
            };

            void test(Widget *widget) {
                memset(widget, 0, sizeof(Widget));
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "bugprone/unsafe-memory-operation");
}

TEST(BugproneUnsafeMemoryOperationRuleTest, IgnoresMemcpyOnTrivialType) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneUnsafeMemoryOperationRule>(),
        R"cpp(
            extern "C" void *memcpy(void *, const void *, unsigned long);

            struct PlainOldData {
                int value;
            };

            void test(PlainOldData *dst, const PlainOldData *src) {
                memcpy(dst, src, sizeof(PlainOldData));
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}
