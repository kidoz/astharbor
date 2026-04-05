#include <gtest/gtest.h>

#include "../../src/rules/best_practice/explicit_single_arg_ctor.hpp"
#include "../../src/rules/best_practice/no_raw_new_delete.hpp"
#include "../../src/rules/bugprone/assignment_in_condition.hpp"
#include "../../src/rules/bugprone/suspicious_semicolon.hpp"
#include "../../src/rules/bugprone/unsafe_memory_operation.hpp"
#include "../../src/rules/modernize/use_override.hpp"
#include "../../src/rules/portability/vla_in_cxx.hpp"
#include "../../src/rules/readability/container_size_empty.hpp"
#include "../../src/rules/readability/use_using_alias.hpp"
#include "../../src/rules/ub/c_style_cast_pointer_punning.hpp"
#include "../../src/rules/ub/casting_through_void.hpp"
#include "../../src/rules/ub/move_of_const.hpp"
#include "../../src/rules/ub/sizeof_array_parameter.hpp"
#include "../../src/rules/ub/delete_non_virtual_dtor.hpp"
#include "../../src/rules/ub/division_by_zero_literal.hpp"
#include "../../src/rules/ub/implicit_widening_multiplication.hpp"
#include "../../src/rules/ub/missing_return_in_non_void.hpp"
#include "../../src/rules/ub/new_delete_array_mismatch.hpp"
#include "../../src/rules/ub/noreturn_function_returns.hpp"
#include "../../src/rules/ub/pointer_arithmetic_on_polymorphic.hpp"
#include "../../src/rules/ub/reinterpret_cast_type_punning.hpp"
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

// ─── Wave 2 UB rules ───────────────────────────────────────────────────

TEST(UbNewDeleteArrayMismatchRuleTest, DetectsNewArrayScalarDelete) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNewDeleteArrayMismatchRule>(),
        R"cpp(
            void test() {
                int *arr = new int[10];
                delete arr;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/new-delete-array-mismatch");
    ASSERT_EQ(result.findings.front().fixes.size(), 1u);
    EXPECT_EQ(result.findings.front().fixes.front().safety, "safe");
    EXPECT_EQ(result.findings.front().fixes.front().replacementText, "delete[]");
}

TEST(UbNewDeleteArrayMismatchRuleTest, DetectsNewScalarArrayDelete) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNewDeleteArrayMismatchRule>(),
        R"cpp(
            void test() {
                int *p = new int;
                delete[] p;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
}

TEST(UbNewDeleteArrayMismatchRuleTest, IgnoresMatchedForms) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNewDeleteArrayMismatchRule>(),
        R"cpp(
            void test() {
                int *arr = new int[10];
                delete[] arr;
                int *p = new int;
                delete p;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbPointerArithmeticOnPolymorphicRuleTest, DetectsIncrement) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbPointerArithmeticOnPolymorphicRule>(),
        R"cpp(
            class Base {
            public:
                virtual void foo();
                virtual ~Base();
            };
            void test(Base *p) {
                p++;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_GE(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/pointer-arithmetic-on-polymorphic");
}

TEST(UbPointerArithmeticOnPolymorphicRuleTest, DetectsSubscript) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbPointerArithmeticOnPolymorphicRule>(),
        R"cpp(
            class Base {
            public:
                virtual void foo();
                virtual ~Base();
            };
            int test(Base *p) {
                (void)p[2];
                return 0;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_GE(result.findings.size(), 1u);
}

TEST(UbPointerArithmeticOnPolymorphicRuleTest, IgnoresNonPolymorphic) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbPointerArithmeticOnPolymorphicRule>(),
        R"cpp(
            struct Plain { int x; };
            void test(Plain *p) {
                p++;
                (void)p[2];
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbImplicitWideningMultiplicationRuleTest, DetectsIntToLongLongWiden) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbImplicitWideningMultiplicationRule>(),
        R"cpp(
            long long test(int a, int b) {
                long long r = a * b;
                return r;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/implicit-widening-multiplication");
}

TEST(UbImplicitWideningMultiplicationRuleTest, IgnoresSameWidthMultiplication) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbImplicitWideningMultiplicationRule>(),
        R"cpp(
            int test(int a, int b) {
                int r = a * b;
                return r;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbImplicitWideningMultiplicationRuleTest, IgnoresPreCastOperand) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbImplicitWideningMultiplicationRule>(),
        R"cpp(
            long long test(int a, int b) {
                long long r = static_cast<long long>(a) * b;
                return r;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbNoreturnFunctionReturnsRuleTest, DetectsReturnInNoreturnFunction) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNoreturnFunctionReturnsRule>(),
        R"cpp(
            [[noreturn]] void fatal() {
                return;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/noreturn-function-returns");
}

TEST(UbNoreturnFunctionReturnsRuleTest, IgnoresNormalFunction) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNoreturnFunctionReturnsRule>(),
        R"cpp(
            int normal() {
                return 42;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbReinterpretCastTypePunningRuleTest, DetectsFloatToIntCast) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbReinterpretCastTypePunningRule>(),
        R"cpp(
            int test(float *p) {
                return *reinterpret_cast<int *>(p);
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/reinterpret-cast-type-punning");
}

TEST(UbReinterpretCastTypePunningRuleTest, IgnoresCastToCharPointer) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbReinterpretCastTypePunningRule>(),
        R"cpp(
            char *test(int *p) {
                return reinterpret_cast<char *>(p);
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbReinterpretCastTypePunningRuleTest, IgnoresRelatedClassCast) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbReinterpretCastTypePunningRule>(),
        R"cpp(
            struct Base { int x; };
            struct Derived : Base { int y; };
            Derived *test(Base *p) {
                return reinterpret_cast<Derived *>(p);
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

// ─── Autofixes on existing rules ───────────────────────────────────────

TEST(ModernizeUseOverrideRuleTest, ProducesOverrideAutofix) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ModernizeUseOverrideRule>(),
        R"cpp(
            class Base {
            public:
                virtual void foo();
                virtual void bar() const;
                virtual ~Base() {}
            };
            class Derived : public Base {
            public:
                void foo();
                void bar() const;
            };
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 2u);
    for (const auto &finding : result.findings) {
        ASSERT_EQ(finding.fixes.size(), 1u);
        EXPECT_EQ(finding.fixes.front().safety, "safe");
        EXPECT_EQ(finding.fixes.front().replacementText, " override");
        EXPECT_EQ(finding.fixes.front().length, 0);
    }
}

TEST(ReadabilityContainerSizeEmptyRuleTest, ProducesEmptyAutofixForEq) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ReadabilityContainerSizeEmptyRule>(),
        R"cpp(
            struct Container {
                unsigned size() const { return 0; }
                bool empty() const { return true; }
            };
            void test() {
                Container c;
                if (c.size() == 0) {}
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    ASSERT_EQ(result.findings.front().fixes.size(), 1u);
    EXPECT_EQ(result.findings.front().fixes.front().safety, "safe");
    EXPECT_EQ(result.findings.front().fixes.front().replacementText, "c.empty()");
}

TEST(ReadabilityContainerSizeEmptyRuleTest, ProducesNotEmptyAutofixForNe) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ReadabilityContainerSizeEmptyRule>(),
        R"cpp(
            struct Container {
                unsigned size() const { return 0; }
                bool empty() const { return true; }
            };
            void test() {
                Container c;
                if (c.size() != 0) {}
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    ASSERT_EQ(result.findings.front().fixes.size(), 1u);
    EXPECT_EQ(result.findings.front().fixes.front().replacementText, "!c.empty()");
}

TEST(ReadabilityContainerSizeEmptyRuleTest, HandlesReversedOperands) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ReadabilityContainerSizeEmptyRule>(),
        R"cpp(
            struct Container {
                unsigned size() const { return 0; }
                bool empty() const { return true; }
            };
            void test() {
                Container c;
                if (0 < c.size()) {}
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    ASSERT_EQ(result.findings.front().fixes.size(), 1u);
    EXPECT_EQ(result.findings.front().fixes.front().replacementText, "!c.empty()");
}

// ─── Missing initial rule coverage ─────────────────────────────────

TEST(ReadabilityUseUsingAliasRuleTest, DetectsSimpleTypedef) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ReadabilityUseUsingAliasRule>(),
        R"cpp(
            typedef int MyInt;
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "readability/use-using-alias");
    ASSERT_EQ(result.findings.front().fixes.size(), 1u);
    EXPECT_EQ(result.findings.front().fixes.front().safety, "review");
    EXPECT_EQ(result.findings.front().fixes.front().replacementText,
              "using MyInt = int");
}

TEST(ReadabilityUseUsingAliasRuleTest, NoAutofixForFunctionPointerTypedef) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ReadabilityUseUsingAliasRule>(),
        R"cpp(
            typedef int (*Callback)(int);
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    // Complex type — diagnostic only, no autofix.
    EXPECT_TRUE(result.findings.front().fixes.empty());
}

TEST(PortabilityVlaInCxxRuleTest, DetectsVlaInCpp) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PortabilityVlaInCxxRule>(),
        R"cpp(
            void test(int n) {
                int arr[n];
                (void)arr;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "portability/vla-in-cxx");
}

TEST(PortabilityVlaInCxxRuleTest, IgnoresFixedSizeArray) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PortabilityVlaInCxxRule>(),
        R"cpp(
            void test() {
                int arr[10];
                (void)arr;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(BestPracticeNoRawNewDeleteRuleTest, DetectsRawNewAndDelete) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeNoRawNewDeleteRule>(),
        R"cpp(
            void test() {
                int *p = new int(42);
                delete p;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    // Expect both the new and delete to be flagged.
    ASSERT_EQ(result.findings.size(), 2u);
}

TEST(BestPracticeNoRawNewDeleteRuleTest, IgnoresPlacementNew) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeNoRawNewDeleteRule>(),
        R"cpp(
            void *operator new(unsigned long, void *p) noexcept { return p; }
            struct Widget { int value; };
            void test(void *buffer) {
                Widget *w = new (buffer) Widget;
                (void)w;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    // Placement new should not be flagged.
    EXPECT_TRUE(result.findings.empty());
}

TEST(BestPracticeExplicitSingleArgCtorRuleTest, DetectsImplicitSingleArgCtor) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeExplicitSingleArgCtorRule>(),
        R"cpp(
            class Widget {
              public:
                Widget(int value);
            };
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId,
              "best-practice/explicit-single-arg-ctor");
    ASSERT_EQ(result.findings.front().fixes.size(), 1u);
    EXPECT_EQ(result.findings.front().fixes.front().replacementText, "explicit ");
}

TEST(BestPracticeExplicitSingleArgCtorRuleTest, IgnoresExplicitCtor) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeExplicitSingleArgCtorRule>(),
        R"cpp(
            class Widget {
              public:
                explicit Widget(int value);
            };
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(BestPracticeExplicitSingleArgCtorRuleTest, IgnoresCopyConstructor) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeExplicitSingleArgCtorRule>(),
        R"cpp(
            class Widget {
              public:
                Widget(const Widget &other);
            };
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

// ─── Wave 3 UB rules ───────────────────────────────────────────────────

TEST(UbCStyleCastPointerPunningRuleTest, DetectsFloatToIntPunning) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbCStyleCastPointerPunningRule>(),
        R"cpp(
            int test(float *p) {
                return *(int *)p;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/c-style-cast-pointer-punning");
}

TEST(UbCStyleCastPointerPunningRuleTest, IgnoresCastToChar) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbCStyleCastPointerPunningRule>(),
        R"cpp(
            char *test(int *p) {
                return (char *)p;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbCastingThroughVoidRuleTest, DetectsStaticCastChain) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbCastingThroughVoidRule>(),
        R"cpp(
            int test(float *p) {
                return *static_cast<int *>(static_cast<void *>(p));
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_GE(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/casting-through-void");
}

TEST(UbCastingThroughVoidRuleTest, IgnoresSingleStaticCast) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbCastingThroughVoidRule>(),
        R"cpp(
            void *test(int *p) {
                return static_cast<void *>(p);
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbMoveOfConstRuleTest, DetectsMoveOfConstLvalue) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMoveOfConstRule>(),
        R"cpp(
            namespace std {
                template <typename T> T&& move(T& t);
                template <typename T> T&& move(const T& t);
            }
            struct Item { int x; };
            void test() {
                const Item a{1};
                Item b(std::move(a));
                (void)b;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/move-of-const");
}

TEST(UbMoveOfConstRuleTest, IgnoresMoveOfNonConstLvalue) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMoveOfConstRule>(),
        R"cpp(
            namespace std {
                template <typename T> T&& move(T& t);
            }
            struct Item { int x; };
            void test() {
                Item a{1};
                Item b(std::move(a));
                (void)b;
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}

TEST(UbSizeofArrayParameterRuleTest, DetectsSizeofArrayParam) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbSizeofArrayParameterRule>(),
        R"cpp(
            unsigned long test(int arr[100]) {
                return sizeof(arr);
            }
        )cpp");

    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.findings.size(), 1u);
    EXPECT_EQ(result.findings.front().ruleId, "ub/sizeof-array-parameter");
}

TEST(UbSizeofArrayParameterRuleTest, IgnoresSizeofLocalArray) {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbSizeofArrayParameterRule>(),
        R"cpp(
            unsigned long test() {
                int arr[100];
                return sizeof(arr);
            }
        )cpp");

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.findings.empty());
}
