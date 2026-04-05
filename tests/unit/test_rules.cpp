#include <gtest/gtest.h>

#include "../../src/rules/bugprone/assignment_in_condition.hpp"
#include "../../src/rules/bugprone/suspicious_semicolon.hpp"
#include "../../src/rules/bugprone/unsafe_memory_operation.hpp"
#include "../../src/rules/ub/delete_non_virtual_dtor.hpp"
#include "../../src/rules/ub/division_by_zero_literal.hpp"
#include "../../src/rules/ub/missing_return_in_non_void.hpp"
#include "../../src/rules/ub/shift_by_negative.hpp"
#include "../../src/rules/ub/shift_past_bitwidth.hpp"
#include "../../src/rules/ub/static_array_oob_constant.hpp"
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

// ─── UB rules ──────────────────────────────────────────────────────────

TEST(UbMissingReturnInNonVoidRuleTest, DetectsFunctionWithNoReturn) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMissingReturnInNonVoidRule>(),
        R"cpp(
            int compute(int x) {
                int y = x + 1;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/missing-return-in-non-void");
}

TEST(UbMissingReturnInNonVoidRuleTest, IgnoresFunctionWithReturn) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMissingReturnInNonVoidRule>(),
        R"cpp(
            int compute(int x) {
                return x + 1;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbMissingReturnInNonVoidRuleTest, IgnoresVoidFunction) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMissingReturnInNonVoidRule>(),
        R"cpp(
            void doNothing() {
                int y = 1;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbMissingReturnInNonVoidRuleTest, IgnoresMain) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMissingReturnInNonVoidRule>(),
        R"cpp(
            int main() {
                int y = 1;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbDivisionByZeroLiteralRuleTest, DetectsDivisionByLiteralZero) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDivisionByZeroLiteralRule>(),
        R"cpp(
            int test(int x) {
                return x / 0;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/division-by-zero-literal");
}

TEST(UbDivisionByZeroLiteralRuleTest, DetectsModuloByLiteralZero) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDivisionByZeroLiteralRule>(),
        R"cpp(
            int test(int x) {
                return x % 0;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
}

TEST(UbDivisionByZeroLiteralRuleTest, IgnoresNonZeroDivisor) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDivisionByZeroLiteralRule>(),
        R"cpp(
            int test(int x) {
                return x / 2;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbShiftByNegativeRuleTest, DetectsShiftByNegativeLiteral) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftByNegativeRule>(),
        R"cpp(
            int test(int x) {
                return x << -1;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/shift-by-negative");
}

TEST(UbShiftByNegativeRuleTest, IgnoresPositiveShift) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftByNegativeRule>(),
        R"cpp(
            int test(int x) {
                return x << 3;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbShiftPastBitwidthRuleTest, DetectsShiftEqualToBitwidth) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftPastBitwidthRule>(),
        R"cpp(
            int test(int x) {
                return x << 32;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/shift-past-bitwidth");
}

TEST(UbShiftPastBitwidthRuleTest, DetectsShiftGreaterThanBitwidth) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftPastBitwidthRule>(),
        R"cpp(
            int test(int x) {
                return x << 64;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
}

TEST(UbShiftPastBitwidthRuleTest, IgnoresValidShift) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftPastBitwidthRule>(),
        R"cpp(
            int test(int x) {
                return x << 5;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbStaticArrayOobConstantRuleTest, DetectsIndexPastEnd) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbStaticArrayOobConstantRule>(),
        R"cpp(
            int test() {
                int arr[10];
                return arr[15];
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/static-array-oob-constant");
}

TEST(UbStaticArrayOobConstantRuleTest, DetectsIndexEqualToSize) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbStaticArrayOobConstantRule>(),
        R"cpp(
            int test() {
                int arr[10];
                return arr[10];
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
}

TEST(UbStaticArrayOobConstantRuleTest, IgnoresValidIndex) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbStaticArrayOobConstantRule>(),
        R"cpp(
            int test() {
                int arr[10];
                return arr[5];
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbDeleteNonVirtualDtorRuleTest, DetectsPolymorphicClassWithNonVirtualDtor) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDeleteNonVirtualDtorRule>(),
        R"cpp(
            class Base {
            public:
                virtual void foo();
                ~Base() {}
            };
            void del(Base *p) {
                delete p;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/delete-non-virtual-dtor");
}

TEST(UbDeleteNonVirtualDtorRuleTest, IgnoresVirtualDestructor) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDeleteNonVirtualDtorRule>(),
        R"cpp(
            class Base {
            public:
                virtual void foo();
                virtual ~Base() {}
            };
            void del(Base *p) {
                delete p;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbDeleteNonVirtualDtorRuleTest, IgnoresNonPolymorphicClass) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDeleteNonVirtualDtorRule>(),
        R"cpp(
            class Plain {
            public:
                int data;
            };
            void del(Plain *p) {
                delete p;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}
