#include <catch2/catch_test_macros.hpp>

#include "../../src/rules/best_practice/explicit_single_arg_ctor.hpp"
#include "../../src/rules/best_practice/no_raw_new_delete.hpp"
#include "../../src/rules/bugprone/assignment_in_condition.hpp"
#include "../../src/rules/bugprone/suspicious_semicolon.hpp"
#include "../../src/rules/bugprone/swapped_arguments.hpp"
#include "../../src/rules/bugprone/sizeof_pointer_in_memfunc.hpp"
#include "../../src/rules/bugprone/char_eof_comparison.hpp"
#include "../../src/rules/bugprone/narrow_wide_char_mismatch.hpp"
#include "../../src/rules/bugprone/unsafe_memory_operation.hpp"
#include "../../src/rules/security/integer_overflow_in_malloc.hpp"
#include "../../src/rules/performance/string_concat_in_loop.hpp"
#include "../../src/rules/modernize/use_override.hpp"
#include "../../src/rules/portability/vla_in_cxx.hpp"
#include "../../src/rules/portability/c_style_variadic.hpp"
#include "../../src/rules/readability/container_size_empty.hpp"
#include "../../src/rules/readability/use_using_alias.hpp"
#include "../../src/rules/ub/c_style_cast_pointer_punning.hpp"
#include "../../src/rules/ub/casting_through_void.hpp"
#include "../../src/rules/ub/move_of_const.hpp"
#include "../../src/rules/ub/sizeof_array_parameter.hpp"
#include "../../src/rules/ub/use_after_move.hpp"
#include "../../src/rules/ub/use_after_free.hpp"
#include "../../src/rules/ub/free_of_non_heap.hpp"
#include "../../src/rules/ub/double_free_local.hpp"
#include "../../src/rules/ub/uninitialized_local.hpp"
#include "../../src/rules/ub/null_deref_after_check.hpp"
#include "../../src/rules/ub/dangling_reference.hpp"
#include "../../src/rules/ub/virtual_call_in_ctor_dtor.hpp"
#include "../../src/rules/resource/leak_on_throw.hpp"
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

TEST_CASE("BugproneAssignmentInConditionRuleTest.DetectsAssignmentInsideIfCondition") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "bugprone/assignment-in-condition");
}

TEST_CASE("BugproneAssignmentInConditionRuleTest.IgnoresEqualityComparisons") {
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

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneSuspiciousSemicolonRuleTest.DetectsEmptyIfBody") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "bugprone/suspicious-semicolon");
}

TEST_CASE("BugproneSuspiciousSemicolonRuleTest.IgnoresNonEmptyIfBody") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSuspiciousSemicolonRule>(),
        R"cpp(
            void test(bool flag) {
                if (flag) {
                    (void)flag;
                }
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneUnsafeMemoryOperationRuleTest.DetectsMemsetOnNonTrivialType") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "bugprone/unsafe-memory-operation");
}

TEST_CASE("BugproneUnsafeMemoryOperationRuleTest.IgnoresMemcpyOnTrivialType") {
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

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── UB rules ──────────────────────────────────────────────────────────

TEST_CASE("UbMissingReturnInNonVoidRuleTest.DetectsFunctionWithNoReturn") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMissingReturnInNonVoidRule>(),
        R"cpp(
            int compute(int x) {
                int y = x + 1;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/missing-return-in-non-void");
}

TEST_CASE("UbMissingReturnInNonVoidRuleTest.IgnoresFunctionWithReturn") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMissingReturnInNonVoidRule>(),
        R"cpp(
            int compute(int x) {
                return x + 1;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbMissingReturnInNonVoidRuleTest.IgnoresVoidFunction") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMissingReturnInNonVoidRule>(),
        R"cpp(
            void doNothing() {
                int y = 1;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbMissingReturnInNonVoidRuleTest.IgnoresMain") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbMissingReturnInNonVoidRule>(),
        R"cpp(
            int main() {
                int y = 1;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbDivisionByZeroLiteralRuleTest.DetectsDivisionByLiteralZero") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDivisionByZeroLiteralRule>(),
        R"cpp(
            int test(int x) {
                return x / 0;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/division-by-zero-literal");
}

TEST_CASE("UbDivisionByZeroLiteralRuleTest.DetectsModuloByLiteralZero") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDivisionByZeroLiteralRule>(),
        R"cpp(
            int test(int x) {
                return x % 0;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbDivisionByZeroLiteralRuleTest.IgnoresNonZeroDivisor") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDivisionByZeroLiteralRule>(),
        R"cpp(
            int test(int x) {
                return x / 2;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbShiftByNegativeRuleTest.DetectsShiftByNegativeLiteral") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftByNegativeRule>(),
        R"cpp(
            int test(int x) {
                return x << -1;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/shift-by-negative");
}

TEST_CASE("UbShiftByNegativeRuleTest.IgnoresPositiveShift") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftByNegativeRule>(),
        R"cpp(
            int test(int x) {
                return x << 3;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbShiftPastBitwidthRuleTest.DetectsShiftEqualToBitwidth") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftPastBitwidthRule>(),
        R"cpp(
            int test(int x) {
                return x << 32;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/shift-past-bitwidth");
}

TEST_CASE("UbShiftPastBitwidthRuleTest.DetectsShiftGreaterThanBitwidth") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftPastBitwidthRule>(),
        R"cpp(
            int test(int x) {
                return x << 64;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbShiftPastBitwidthRuleTest.IgnoresValidShift") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbShiftPastBitwidthRule>(),
        R"cpp(
            int test(int x) {
                return x << 5;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbStaticArrayOobConstantRuleTest.DetectsIndexPastEnd") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbStaticArrayOobConstantRule>(),
        R"cpp(
            int test() {
                int arr[10];
                return arr[15];
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/static-array-oob-constant");
}

TEST_CASE("UbStaticArrayOobConstantRuleTest.DetectsIndexEqualToSize") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbStaticArrayOobConstantRule>(),
        R"cpp(
            int test() {
                int arr[10];
                return arr[10];
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbStaticArrayOobConstantRuleTest.IgnoresValidIndex") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbStaticArrayOobConstantRule>(),
        R"cpp(
            int test() {
                int arr[10];
                return arr[5];
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbDeleteNonVirtualDtorRuleTest.DetectsPolymorphicClassWithNonVirtualDtor") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/delete-non-virtual-dtor");
}

TEST_CASE("UbDeleteNonVirtualDtorRuleTest.IgnoresVirtualDestructor") {
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

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbDeleteNonVirtualDtorRuleTest.IgnoresNonPolymorphicClass") {
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

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── Wave 2 UB rules ───────────────────────────────────────────────────

TEST_CASE("UbNewDeleteArrayMismatchRuleTest.DetectsNewArrayScalarDelete") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNewDeleteArrayMismatchRule>(),
        R"cpp(
            void test() {
                int *arr = new int[10];
                delete arr;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/new-delete-array-mismatch");
    REQUIRE(result.findings.front().fixes.size() == 1u);
    CHECK(result.findings.front().fixes.front().safety == "safe");
    CHECK(result.findings.front().fixes.front().replacementText == "delete[]");
}

TEST_CASE("UbNewDeleteArrayMismatchRuleTest.DetectsNewScalarArrayDelete") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNewDeleteArrayMismatchRule>(),
        R"cpp(
            void test() {
                int *p = new int;
                delete[] p;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbNewDeleteArrayMismatchRuleTest.IgnoresMatchedForms") {
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

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbPointerArithmeticOnPolymorphicRuleTest.DetectsIncrement") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() >= 1u);
    CHECK(result.findings.front().ruleId == "ub/pointer-arithmetic-on-polymorphic");
}

TEST_CASE("UbPointerArithmeticOnPolymorphicRuleTest.DetectsSubscript") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() >= 1u);
}

TEST_CASE("UbPointerArithmeticOnPolymorphicRuleTest.IgnoresNonPolymorphic") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbPointerArithmeticOnPolymorphicRule>(),
        R"cpp(
            struct Plain { int x; };
            void test(Plain *p) {
                p++;
                (void)p[2];
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbImplicitWideningMultiplicationRuleTest.DetectsIntToLongLongWiden") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbImplicitWideningMultiplicationRule>(),
        R"cpp(
            long long test(int a, int b) {
                long long r = a * b;
                return r;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/implicit-widening-multiplication");
}

TEST_CASE("UbImplicitWideningMultiplicationRuleTest.IgnoresSameWidthMultiplication") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbImplicitWideningMultiplicationRule>(),
        R"cpp(
            int test(int a, int b) {
                int r = a * b;
                return r;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbImplicitWideningMultiplicationRuleTest.IgnoresPreCastOperand") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbImplicitWideningMultiplicationRule>(),
        R"cpp(
            long long test(int a, int b) {
                long long r = static_cast<long long>(a) * b;
                return r;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbNoreturnFunctionReturnsRuleTest.DetectsReturnInNoreturnFunction") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNoreturnFunctionReturnsRule>(),
        R"cpp(
            [[noreturn]] void fatal() {
                return;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/noreturn-function-returns");
}

TEST_CASE("UbNoreturnFunctionReturnsRuleTest.IgnoresNormalFunction") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNoreturnFunctionReturnsRule>(),
        R"cpp(
            int normal() {
                return 42;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbReinterpretCastTypePunningRuleTest.DetectsFloatToIntCast") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbReinterpretCastTypePunningRule>(),
        R"cpp(
            int test(float *p) {
                return *reinterpret_cast<int *>(p);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/reinterpret-cast-type-punning");
}

TEST_CASE("UbReinterpretCastTypePunningRuleTest.IgnoresCastToCharPointer") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbReinterpretCastTypePunningRule>(),
        R"cpp(
            char *test(int *p) {
                return reinterpret_cast<char *>(p);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbReinterpretCastTypePunningRuleTest.IgnoresRelatedClassCast") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbReinterpretCastTypePunningRule>(),
        R"cpp(
            struct Base { int x; };
            struct Derived : Base { int y; };
            Derived *test(Base *p) {
                return reinterpret_cast<Derived *>(p);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── Autofixes on existing rules ───────────────────────────────────────

TEST_CASE("ModernizeUseOverrideRuleTest.ProducesOverrideAutofix") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 2u);
    for (const auto &finding : result.findings) {
        REQUIRE(finding.fixes.size() == 1u);
        CHECK(finding.fixes.front().safety == "safe");
        CHECK(finding.fixes.front().replacementText == " override");
        CHECK(finding.fixes.front().length == 0);
    }
}

TEST_CASE("ReadabilityContainerSizeEmptyRuleTest.ProducesEmptyAutofixForEq") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    REQUIRE(result.findings.front().fixes.size() == 1u);
    CHECK(result.findings.front().fixes.front().safety == "safe");
    CHECK(result.findings.front().fixes.front().replacementText == "c.empty()");
}

TEST_CASE("ReadabilityContainerSizeEmptyRuleTest.ProducesNotEmptyAutofixForNe") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    REQUIRE(result.findings.front().fixes.size() == 1u);
    CHECK(result.findings.front().fixes.front().replacementText == "!c.empty()");
}

TEST_CASE("ReadabilityContainerSizeEmptyRuleTest.HandlesReversedOperands") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    REQUIRE(result.findings.front().fixes.size() == 1u);
    CHECK(result.findings.front().fixes.front().replacementText == "!c.empty()");
}

// ─── Missing initial rule coverage ─────────────────────────────────

TEST_CASE("ReadabilityUseUsingAliasRuleTest.DetectsSimpleTypedef") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ReadabilityUseUsingAliasRule>(),
        R"cpp(
            typedef int MyInt;
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "readability/use-using-alias");
    REQUIRE(result.findings.front().fixes.size() == 1u);
    CHECK(result.findings.front().fixes.front().safety == "review");
    CHECK(result.findings.front().fixes.front().replacementText == "using MyInt = int");
}

TEST_CASE("ReadabilityUseUsingAliasRuleTest.NoAutofixForFunctionPointerTypedef") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ReadabilityUseUsingAliasRule>(),
        R"cpp(
            typedef int (*Callback)(int);
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    // Complex type — diagnostic only, no autofix.
    CHECK(result.findings.front().fixes.empty());
}

TEST_CASE("PortabilityVlaInCxxRuleTest.DetectsVlaInCpp") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PortabilityVlaInCxxRule>(),
        R"cpp(
            void test(int n) {
                int arr[n];
                (void)arr;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "portability/vla-in-cxx");
}

TEST_CASE("PortabilityVlaInCxxRuleTest.IgnoresFixedSizeArray") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PortabilityVlaInCxxRule>(),
        R"cpp(
            void test() {
                int arr[10];
                (void)arr;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BestPracticeNoRawNewDeleteRuleTest.DetectsRawNewAndDelete") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeNoRawNewDeleteRule>(),
        R"cpp(
            void test() {
                int *p = new int(42);
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    // Expect both the new and delete to be flagged.
    REQUIRE(result.findings.size() == 2u);
}

TEST_CASE("BestPracticeNoRawNewDeleteRuleTest.IgnoresPlacementNew") {
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

    REQUIRE(result.success);
    // Placement new should not be flagged.
    CHECK(result.findings.empty());
}

TEST_CASE("BestPracticeExplicitSingleArgCtorRuleTest.DetectsImplicitSingleArgCtor") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeExplicitSingleArgCtorRule>(),
        R"cpp(
            class Widget {
              public:
                Widget(int value);
            };
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "best-practice/explicit-single-arg-ctor");
    REQUIRE(result.findings.front().fixes.size() == 1u);
    CHECK(result.findings.front().fixes.front().replacementText == "explicit ");
}

TEST_CASE("BestPracticeExplicitSingleArgCtorRuleTest.IgnoresExplicitCtor") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeExplicitSingleArgCtorRule>(),
        R"cpp(
            class Widget {
              public:
                explicit Widget(int value);
            };
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BestPracticeExplicitSingleArgCtorRuleTest.IgnoresCopyConstructor") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BestPracticeExplicitSingleArgCtorRule>(),
        R"cpp(
            class Widget {
              public:
                Widget(const Widget &other);
            };
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── Wave 3 UB rules ───────────────────────────────────────────────────

TEST_CASE("UbCStyleCastPointerPunningRuleTest.DetectsFloatToIntPunning") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbCStyleCastPointerPunningRule>(),
        R"cpp(
            int test(float *p) {
                return *(int *)p;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/c-style-cast-pointer-punning");
}

TEST_CASE("UbCStyleCastPointerPunningRuleTest.IgnoresCastToChar") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbCStyleCastPointerPunningRule>(),
        R"cpp(
            char *test(int *p) {
                return (char *)p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbCastingThroughVoidRuleTest.DetectsStaticCastChain") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbCastingThroughVoidRule>(),
        R"cpp(
            int test(float *p) {
                return *static_cast<int *>(static_cast<void *>(p));
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() >= 1u);
    CHECK(result.findings.front().ruleId == "ub/casting-through-void");
}

TEST_CASE("UbCastingThroughVoidRuleTest.IgnoresSingleStaticCast") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbCastingThroughVoidRule>(),
        R"cpp(
            void *test(int *p) {
                return static_cast<void *>(p);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbMoveOfConstRuleTest.DetectsMoveOfConstLvalue") {
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

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/move-of-const");
}

TEST_CASE("UbMoveOfConstRuleTest.IgnoresMoveOfNonConstLvalue") {
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

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbSizeofArrayParameterRuleTest.DetectsSizeofArrayParam") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbSizeofArrayParameterRule>(),
        R"cpp(
            unsigned long test(int arr[100]) {
                return sizeof(arr);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/sizeof-array-parameter");
}

TEST_CASE("UbSizeofArrayParameterRuleTest.IgnoresSizeofLocalArray") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbSizeofArrayParameterRule>(),
        R"cpp(
            unsigned long test() {
                int arr[100];
                return sizeof(arr);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── use-after-move (Tier 2) ───────────────────────────────────────────

TEST_CASE("UbUseAfterMoveRuleTest.DetectsUseAfterMove") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterMoveRule>(),
        R"cpp(
            namespace std {
                template <typename T> T&& move(T& t);
                template <typename T> T&& move(const T& t);
            }
            struct Widget { int data; };
            int bad() {
                Widget w{42};
                Widget b(std::move(w));
                (void)b;
                return w.data;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/use-after-move");
}

TEST_CASE("UbUseAfterMoveRuleTest.IgnoresReassignmentBeforeReuse") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterMoveRule>(),
        R"cpp(
            namespace std {
                template <typename T> T&& move(T& t);
                template <typename T> T&& move(const T& t);
            }
            struct Widget { int data; };
            int ok() {
                Widget w{42};
                Widget b(std::move(w));
                (void)b;
                w = Widget{100};
                return w.data;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbUseAfterMoveRuleTest.IgnoresMoveWithNoSubsequentUse") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterMoveRule>(),
        R"cpp(
            namespace std {
                template <typename T> T&& move(T& t);
                template <typename T> T&& move(const T& t);
            }
            struct Widget { int data; };
            void ok() {
                Widget w{42};
                Widget b(std::move(w));
                (void)b;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbUseAfterMoveRuleTest.IgnoresMoveInBranchWithEarlyReturn") {
    // CFG-based analysis: the use after the if-branch is unreachable from
    // the move inside the branch because the branch returns. The previous
    // source-order visitor flagged this as a false positive.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterMoveRule>(),
        R"cpp(
            namespace std {
                template <typename T> T&& move(T& t);
                template <typename T> T&& move(const T& t);
            }
            struct Widget { int data; };
            int test(Widget w, bool cond) {
                if (cond) {
                    Widget b(std::move(w));
                    return 1;
                }
                return w.data;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── double-free-local (Tier 2) ────────────────────────────────────────

TEST_CASE("UbDoubleFreeLocalRuleTest.DetectsSameVariableDeletedTwice") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDoubleFreeLocalRule>(),
        R"cpp(
            void test() {
                int *p = new int(42);
                delete p;
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/double-free-local");
}

TEST_CASE("UbDoubleFreeLocalRuleTest.IgnoresReassignmentBetweenDeletes") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDoubleFreeLocalRule>(),
        R"cpp(
            void test() {
                int *p = new int(42);
                delete p;
                p = new int(100);
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbDoubleFreeLocalRuleTest.IgnoresSingleDelete") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDoubleFreeLocalRule>(),
        R"cpp(
            void test() {
                int *p = new int(42);
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbDoubleFreeLocalRuleTest.IgnoresDeleteInBranchWithEarlyReturn") {
    // The `return` cuts the path from the first delete to the second,
    // so no reachable path double-frees `p`.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDoubleFreeLocalRule>(),
        R"cpp(
            void test(bool flag) {
                int *p = new int(42);
                if (flag) {
                    delete p;
                    return;
                }
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbDoubleFreeLocalRuleTest.DetectsDeleteInBothBranchesAfterMerge") {
    // Both branches delete p, then the merge point deletes again.
    // Every path from the first delete reaches the merge delete, so this
    // is a real double-free.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDoubleFreeLocalRule>(),
        R"cpp(
            void test(bool flag) {
                int *p = new int(42);
                if (flag) {
                    delete p;
                } else {
                    delete p;
                }
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(!(result.findings.empty()));
    CHECK(result.findings.front().ruleId == "ub/double-free-local");
}

// ─── uninitialized-local (Tier 2) ──────────────────────────────────────

TEST_CASE("UbUninitializedLocalRuleTest.DetectsReadBeforeWrite") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUninitializedLocalRule>(),
        R"cpp(
            int test() {
                int x;
                return x + 1;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/uninitialized-local");
}

TEST_CASE("UbUninitializedLocalRuleTest.IgnoresWriteBeforeRead") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUninitializedLocalRule>(),
        R"cpp(
            int test() {
                int x;
                x = 42;
                return x + 1;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbUninitializedLocalRuleTest.IgnoresInitializedVar") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUninitializedLocalRule>(),
        R"cpp(
            int test() {
                int x = 42;
                return x + 1;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbUninitializedLocalRuleTest.IgnoresAddressOfFollowedByRead") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUninitializedLocalRule>(),
        R"cpp(
            extern void init(int* p);
            int test() {
                int x;
                init(&x);
                return x + 1;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbUninitializedLocalRuleTest.DetectsReadOnBranchMissingInit") {
    // One branch writes x, the other does not; the read after the
    // merge is reachable from the unwritten path, so this is a real
    // uninitialized read.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUninitializedLocalRule>(),
        R"cpp(
            int test(bool flag) {
                int x;
                if (flag) {
                    x = 42;
                }
                return x + 1;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(!(result.findings.empty()));
    CHECK(result.findings.front().ruleId == "ub/uninitialized-local");
}

TEST_CASE("UbUninitializedLocalRuleTest.IgnoresWriteInAllBranches") {
    // Both branches write x, so every path to the read has a prior
    // write — no finding.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUninitializedLocalRule>(),
        R"cpp(
            int test(bool flag) {
                int x;
                if (flag) {
                    x = 1;
                } else {
                    x = 2;
                }
                return x + 1;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── null-deref-after-check (Tier 2) ───────────────────────────────────

TEST_CASE("UbNullDerefAfterCheckRuleTest.DetectsArrowDerefInNullBranch") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNullDerefAfterCheckRule>(),
        R"cpp(
            struct S { int field; };
            int test(S *p) {
                if (p == nullptr) {
                    return p->field;
                }
                return 0;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/null-deref-after-check");
}

TEST_CASE("UbNullDerefAfterCheckRuleTest.DetectsStarDerefInNotCheck") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNullDerefAfterCheckRule>(),
        R"cpp(
            int test(int *p) {
                if (!p) {
                    return *p;
                }
                return 0;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbNullDerefAfterCheckRuleTest.DetectsSubscriptInNullBranch") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNullDerefAfterCheckRule>(),
        R"cpp(
            int test(int *p) {
                if (p == 0) {
                    return p[5];
                }
                return 0;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbNullDerefAfterCheckRuleTest.IgnoresEarlyReturnGuard") {
    // The canonical GOOD pattern: early-return on null. The then-block
    // has no dereferences, so BFS finds nothing and the rule stays
    // silent.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNullDerefAfterCheckRule>(),
        R"cpp(
            int test(int *p) {
                if (p == nullptr) {
                    return -1;
                }
                return *p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbNullDerefAfterCheckRuleTest.IgnoresReassignmentBeforeDeref") {
    // `p = &fallback;` restores a non-null value on this path, so the
    // subsequent dereference is safe and should not be reported.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNullDerefAfterCheckRule>(),
        R"cpp(
            int test(int *p) {
                int fallback = 42;
                if (p == nullptr) {
                    p = &fallback;
                    return *p;
                }
                return 0;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbNullDerefAfterCheckRuleTest.IgnoresDerefOutsideThenBranch") {
    // The dereference lives after the `if`, not inside its then-branch,
    // so the check-then-use pattern is fine.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbNullDerefAfterCheckRule>(),
        R"cpp(
            int test(int *p) {
                if (p == nullptr) {
                    return -1;
                }
                return *p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── resource/leak-on-throw (Tier 2) ───────────────────────────────────

TEST_CASE("ResourceLeakOnThrowRuleTest.DetectsLeakWhenThrowFollowsNew") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ResourceLeakOnThrowRule>(),
        R"cpp(
            struct Err { const char *what; };
            void test(bool flag) {
                int *p = new int(42);
                if (flag) {
                    throw Err{"bad"};
                }
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "resource/leak-on-throw");
}

TEST_CASE("ResourceLeakOnThrowRuleTest.IgnoresDeleteBeforeThrow") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ResourceLeakOnThrowRule>(),
        R"cpp(
            struct Err { const char *what; };
            void test(bool flag) {
                int *p = new int(42);
                if (flag) {
                    delete p;
                    throw Err{"bad"};
                }
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("ResourceLeakOnThrowRuleTest.IgnoresFunctionWithTryBlock") {
    // Any `try` in the function suppresses the rule conservatively —
    // the throw might be caught locally and wouldn't actually leak.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ResourceLeakOnThrowRule>(),
        R"cpp(
            struct Err { const char *what; };
            void test(bool flag) {
                int *p = new int(42);
                try {
                    if (flag) {
                        throw Err{"bad"};
                    }
                } catch (...) {}
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("ResourceLeakOnThrowRuleTest.IgnoresNoThrowPath") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ResourceLeakOnThrowRule>(),
        R"cpp(
            void test() {
                int *p = new int(42);
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("ResourceLeakOnThrowRuleTest.IgnoresReassignmentBeforeThrow") {
    // Reassigning `p` transfers ownership away — we can no longer track
    // what the current value points at, so the throw on this path is
    // not our rule's concern.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::ResourceLeakOnThrowRule>(),
        R"cpp(
            struct Err { const char *what; };
            void sink(int *);
            void test(bool flag) {
                int *p = new int(42);
                if (flag) {
                    sink(p);
                    p = nullptr;
                    throw Err{"bad"};
                }
                delete p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── dangling-reference (Tier 2) ───────────────────────────────────────

TEST_CASE("UbDanglingReferenceRuleTest.DetectsReferenceReturnOfLocal") {
    // `const int&` avoids Clang's hard error on binding a non-const
    // reference to a function-local lvalue while still matching the
    // rule's `returns(referenceType())` predicate.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDanglingReferenceRule>(),
        R"cpp(
            const int& test() {
                int x = 42;
                return x;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/dangling-reference");
}

TEST_CASE("UbDanglingReferenceRuleTest.DetectsPointerReturnOfAddressOfLocal") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDanglingReferenceRule>(),
        R"cpp(
            int* test() {
                int x = 42;
                return &x;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbDanglingReferenceRuleTest.DetectsPointerReturnOfArrayDecay") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDanglingReferenceRule>(),
        R"cpp(
            char* test() {
                char buf[16] = "hello";
                return buf;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbDanglingReferenceRuleTest.DetectsReferenceReturnOfByValueParam") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDanglingReferenceRule>(),
        R"cpp(
            const int& test(int x) {
                return x;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbDanglingReferenceRuleTest.IgnoresReferenceReturnOfReferenceParam") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDanglingReferenceRule>(),
        R"cpp(
            int& test(int& x) {
                return x;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbDanglingReferenceRuleTest.IgnoresStaticLocal") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDanglingReferenceRule>(),
        R"cpp(
            int& test() {
                static int x = 42;
                return x;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbDanglingReferenceRuleTest.IgnoresValueReturn") {
    // Copy-by-value is fine even if the source is a local.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbDanglingReferenceRule>(),
        R"cpp(
            int test() {
                int x = 42;
                return x;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── bugprone/swapped-arguments ────────────────────────────────────────

TEST_CASE("BugproneSwappedArgumentsRuleTest.DetectsSwappedDstSrc") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSwappedArgumentsRule>(),
        R"cpp(
            void copy(char *dst, const char *src, unsigned long n);
            void caller() {
                char dst[32];
                char src[32];
                copy(src, dst, 32);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "bugprone/swapped-arguments");
}

TEST_CASE("BugproneSwappedArgumentsRuleTest.IgnoresCorrectArgumentOrder") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSwappedArgumentsRule>(),
        R"cpp(
            void copy(char *dst, const char *src, unsigned long n);
            void caller() {
                char dst[32];
                char src[32];
                copy(dst, src, 32);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneSwappedArgumentsRuleTest.IgnoresSingleLetterParameterNames") {
    // Single-letter names are common and carry no semantic weight; the
    // rule requires length >= 2 on both sides to avoid the noise.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSwappedArgumentsRule>(),
        R"cpp(
            void f(int a, int b);
            void caller() {
                int a = 1, b = 2;
                f(b, a);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneSwappedArgumentsRuleTest.IgnoresLiteralArguments") {
    // A literal in one of the positions means the programmer intended
    // a constant, so the "swap" shape doesn't apply.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSwappedArgumentsRule>(),
        R"cpp(
            void f(int width, int height);
            void caller() {
                int width = 10;
                f(width, 20);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneSwappedArgumentsRuleTest.IgnoresMismatchedNames") {
    // Only one of the two names cross-matches; a single coincidence is
    // not enough for the swap heuristic to fire.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSwappedArgumentsRule>(),
        R"cpp(
            void f(int width, int height);
            void caller() {
                int width = 10;
                int other = 20;
                f(other, width);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneSwappedArgumentsRuleTest.DetectsSwapAmongThreeArguments") {
    // Only the first two are swapped; the third position is untouched.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSwappedArgumentsRule>(),
        R"cpp(
            void draw(int width, int height, int color);
            void caller() {
                int width = 1, height = 2, color = 3;
                draw(height, width, color);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

// ─── security/integer-overflow-in-malloc ───────────────────────────────

TEST_CASE("SecurityIntegerOverflowInMallocRuleTest.DetectsMallocWithVariableTimesSizeof") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::SecurityIntegerOverflowInMallocRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            void *test(unsigned long n) {
                return malloc(n * sizeof(int));
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "security/integer-overflow-in-malloc");
}

TEST_CASE("SecurityIntegerOverflowInMallocRuleTest.IgnoresSignedOperand") {
    // Signed-operand multiplications are owned by
    // security/signed-arith-in-alloc; this rule stays silent to avoid
    // duplicate findings on the same bug.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::SecurityIntegerOverflowInMallocRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            void *test(int n) {
                return malloc(n * sizeof(int));
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("SecurityIntegerOverflowInMallocRuleTest.DetectsUnsignedVarTimesIntLiteral") {
    // Regression: the signed-operand filter must only skip when a
    // NON-CONSTANT signed operand is present. A plain `4` literal is
    // signed `int` but constant, so the multiplication
    // `unsigned_n * 4` is still an unsigned runtime multiplication
    // this rule is supposed to flag.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::SecurityIntegerOverflowInMallocRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            void *test(unsigned long n) {
                return malloc(n * 4);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("SecurityIntegerOverflowInMallocRuleTest.DetectsReallocWithVariableTimesSize") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::SecurityIntegerOverflowInMallocRule>(),
        R"cpp(
            extern "C" void *realloc(void*, unsigned long);
            void *test(void *buf, unsigned long count, unsigned long elem) {
                return realloc(buf, count * elem);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("SecurityIntegerOverflowInMallocRuleTest.IgnoresConstantTimesConstant") {
    // Compile-time-foldable multiplication cannot overflow at runtime.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::SecurityIntegerOverflowInMallocRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            void *test() {
                return malloc(16 * 1024);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("SecurityIntegerOverflowInMallocRuleTest.IgnoresNonMultiplicationSize") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::SecurityIntegerOverflowInMallocRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            void *test(unsigned long n) {
                return malloc(n + 16);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("SecurityIntegerOverflowInMallocRuleTest.IgnoresCallocTwoArgForm") {
    // calloc takes (count, size) as separate args, no multiplication in
    // the AST to match — this is the recommended safe form the rule
    // tells users to migrate TO.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::SecurityIntegerOverflowInMallocRule>(),
        R"cpp(
            extern "C" void *calloc(unsigned long, unsigned long);
            void *test(unsigned long n) {
                return calloc(n, sizeof(int));
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── performance/string-concat-in-loop ─────────────────────────────────

TEST_CASE("PerformanceStringConcatInLoopRuleTest.DetectsForLoopConcat") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PerformanceStringConcatInLoopRule>(),
        R"cpp(
            #include <string>
            std::string join(const char* const* parts, int n) {
                std::string s;
                for (int i = 0; i < n; ++i) {
                    s = s + parts[i];
                }
                return s;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "performance/string-concat-in-loop");
}

TEST_CASE("PerformanceStringConcatInLoopRuleTest.DetectsWhileLoopConcat") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PerformanceStringConcatInLoopRule>(),
        R"cpp(
            #include <string>
            std::string build(int n) {
                std::string s;
                while (n > 0) {
                    s = s + "x";
                    --n;
                }
                return s;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("PerformanceStringConcatInLoopRuleTest.IgnoresPlusEquals") {
    // s += other uses basic_string::append which is amortized linear —
    // this is the recommended fix.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PerformanceStringConcatInLoopRule>(),
        R"cpp(
            #include <string>
            std::string join(const char* const* parts, int n) {
                std::string s;
                for (int i = 0; i < n; ++i) {
                    s += parts[i];
                }
                return s;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("PerformanceStringConcatInLoopRuleTest.IgnoresConcatOutsideLoop") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PerformanceStringConcatInLoopRule>(),
        R"cpp(
            #include <string>
            std::string build() {
                std::string s = "a";
                s = s + "b";
                return s;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("PerformanceStringConcatInLoopRuleTest.IgnoresNonStringType") {
    // `int` has no `operator+` / `operator=` overload — the matcher is
    // scoped to `cxxOperatorCallExpr` which only matches user-defined
    // operators, so built-in types never fire.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PerformanceStringConcatInLoopRule>(),
        R"cpp(
            int sum(int n) {
                int s = 0;
                for (int i = 0; i < n; ++i) {
                    s = s + i;
                }
                return s;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── bugprone/sizeof-pointer-in-memfunc ────────────────────────────────

TEST_CASE("BugproneSizeofPointerInMemfuncRuleTest.DetectsMemmoveWithSizeofPtr") {
    // `memset` is covered by bugprone/suspicious-memset; this rule
    // owns the rest of the mem* family.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSizeofPointerInMemfuncRule>(),
        R"cpp(
            extern "C" void *memmove(void*, const void*, unsigned long);
            void test(int *p, const int *q) {
                memmove(p, q, sizeof(p));
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "bugprone/sizeof-pointer-in-memfunc");
}

TEST_CASE("BugproneSizeofPointerInMemfuncRuleTest.IgnoresMemsetHandledElsewhere") {
    // memset's same-var sizeof case is owned by bugprone/suspicious-
    // memset — this rule must stay silent to avoid duplicate findings.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSizeofPointerInMemfuncRule>(),
        R"cpp(
            extern "C" void *memset(void*, int, unsigned long);
            void test(int *p) {
                memset(p, 0, sizeof(p));
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneSizeofPointerInMemfuncRuleTest.DetectsMemcpyWithSizeofDst") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSizeofPointerInMemfuncRule>(),
        R"cpp(
            extern "C" void *memcpy(void*, const void*, unsigned long);
            void test(int *dst, const int *src) {
                memcpy(dst, src, sizeof(dst));
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("BugproneSizeofPointerInMemfuncRuleTest.DetectsDecayedArrayParam") {
    // `char buf[256]` as a parameter decays to `char*` in the AST, so
    // sizeof(buf) is the pointer size, not 256. Classic footgun.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSizeofPointerInMemfuncRule>(),
        R"cpp(
            extern "C" void *memcpy(void*, const void*, unsigned long);
            void copy(char buf[256], const char *src) {
                memcpy(buf, src, sizeof(buf));
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("BugproneSizeofPointerInMemfuncRuleTest.IgnoresSizeofPointee") {
    // `sizeof(*p)` is the pointee size — the correct idiom.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSizeofPointerInMemfuncRule>(),
        R"cpp(
            extern "C" void *memcpy(void*, const void*, unsigned long);
            void test(int *p, const int *q) {
                memcpy(p, q, sizeof(*p));
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneSizeofPointerInMemfuncRuleTest.IgnoresSizeofOfActualArray") {
    // A true array (not a decayed parameter) has array type, so the
    // buffer var's matcher (pointerType) doesn't bind and the rule
    // stays silent — correct, sizeof(arr) is the full array length.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSizeofPointerInMemfuncRule>(),
        R"cpp(
            extern "C" void *memcpy(void*, const void*, unsigned long);
            void test(const char *src) {
                char buf[256];
                memcpy(buf, src, sizeof(buf));
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneSizeofPointerInMemfuncRuleTest.IgnoresSizeofOfOtherVariable") {
    // The sizeof is taken of a different variable, not the buffer
    // passed as arg 0. Unlikely to be a bug.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneSizeofPointerInMemfuncRule>(),
        R"cpp(
            extern "C" void *memcpy(void*, const void*, unsigned long);
            struct T { int field; };
            void test(T *dst, const T *src) {
                T record;
                memcpy(dst, src, sizeof(record));
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── bugprone/char-eof-comparison (CERT FIO34-C) ──────────────────────

TEST_CASE("BugproneCharEofComparisonRuleTest.DetectsCharInitFromGetchar") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneCharEofComparisonRule>(),
        R"cpp(
            extern "C" int getchar();
            void test() {
                char c = getchar();
                (void)c;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "bugprone/char-eof-comparison");
}

TEST_CASE("BugproneCharEofComparisonRuleTest.DetectsCharAssignFromFgetc") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneCharEofComparisonRule>(),
        R"cpp(
            struct FILE;
            extern "C" int fgetc(FILE*);
            void test(FILE *fp) {
                char c;
                c = fgetc(fp);
                (void)c;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("BugproneCharEofComparisonRuleTest.DetectsUnsignedCharInitFromGetc") {
    // `unsigned char` is where the bug bites hardest — EOF (-1) can
    // never be represented.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneCharEofComparisonRule>(),
        R"cpp(
            struct FILE;
            extern "C" int getc(FILE*);
            void test(FILE *fp) {
                unsigned char c = getc(fp);
                (void)c;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("BugproneCharEofComparisonRuleTest.IgnoresIntTarget") {
    // The correct idiom: store the return in an int so EOF is
    // preserved.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneCharEofComparisonRule>(),
        R"cpp(
            extern "C" int getchar();
            void test() {
                int c = getchar();
                (void)c;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("BugproneCharEofComparisonRuleTest.IgnoresUnrelatedFunction") {
    // A function that happens to return int but isn't from the
    // getchar family is irrelevant.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneCharEofComparisonRule>(),
        R"cpp(
            extern "C" int compute();
            void test() {
                char c = compute();
                (void)c;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── ub/use-after-free (CFG, CERT MEM30-C) ────────────────────────────

TEST_CASE("UbUseAfterFreeRuleTest.DetectsDerefAfterFree") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterFreeRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            extern "C" void free(void*);
            int test() {
                int *p = (int*)malloc(sizeof(int));
                free(p);
                return *p;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/use-after-free");
}

TEST_CASE("UbUseAfterFreeRuleTest.DetectsArrowMemberAfterFree") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterFreeRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            extern "C" void free(void*);
            struct S { int field; };
            int test() {
                S *p = (S*)malloc(sizeof(S));
                free(p);
                return p->field;
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbUseAfterFreeRuleTest.DetectsPassAsCallArgAfterFree") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterFreeRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            extern "C" void free(void*);
            extern void sink(void*);
            void test() {
                void *p = malloc(16);
                free(p);
                sink(p);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbUseAfterFreeRuleTest.IgnoresReassignmentBeforeUse") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterFreeRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            extern "C" void free(void*);
            int test() {
                int *p = (int*)malloc(sizeof(int));
                free(p);
                p = (int*)malloc(sizeof(int));
                return *p;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbUseAfterFreeRuleTest.IgnoresUseOnlyInUnreachableBranch") {
    // The use of p lives inside a then-branch that ends in `return`
    // before the free. On the path after `free(p)`, there are no
    // dereferences of p.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterFreeRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            extern "C" void free(void*);
            int test(bool flag) {
                int *p = (int*)malloc(sizeof(int));
                if (flag) {
                    int v = *p;
                    free(p);
                    return v;
                }
                free(p);
                return 0;
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbUseAfterFreeRuleTest.IgnoresSingleFree") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbUseAfterFreeRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            extern "C" void free(void*);
            void test() {
                int *p = (int*)malloc(sizeof(int));
                free(p);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── ub/free-of-non-heap (CERT MEM34-C) ──────────────────────────────

TEST_CASE("UbFreeOfNonHeapRuleTest.DetectsFreeOfAddressOfLocal") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbFreeOfNonHeapRule>(),
        R"cpp(
            extern "C" void free(void*);
            void test() {
                int x = 42;
                free(&x);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/free-of-non-heap");
}

TEST_CASE("UbFreeOfNonHeapRuleTest.DetectsFreeOfLocalArrayDecay") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbFreeOfNonHeapRule>(),
        R"cpp(
            extern "C" void free(void*);
            void test() {
                char buf[256];
                free(buf);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbFreeOfNonHeapRuleTest.DetectsFreeOfStaticVar") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbFreeOfNonHeapRule>(),
        R"cpp(
            extern "C" void free(void*);
            int global_val = 42;
            void test() {
                free(&global_val);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbFreeOfNonHeapRuleTest.DetectsFreeOfStringLiteral") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbFreeOfNonHeapRule>(),
        R"cpp(
            extern "C" void free(void*);
            void test() {
                free((void*)"hello");
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbFreeOfNonHeapRuleTest.IgnoresHeapPointer") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbFreeOfNonHeapRule>(),
        R"cpp(
            extern "C" void *malloc(unsigned long);
            extern "C" void free(void*);
            void test() {
                void *p = malloc(16);
                free(p);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbFreeOfNonHeapRuleTest.IgnoresPointerParameter") {
    // A pointer parameter could come from anywhere — we can't know
    // whether it was heap-allocated or not.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbFreeOfNonHeapRule>(),
        R"cpp(
            extern "C" void free(void*);
            void test(void *p) {
                free(p);
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── portability/c-style-variadic (CERT DCL50-CPP) ───────────────────

TEST_CASE("PortabilityCStyleVariadicRuleTest.DetectsVariadicDefinition") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PortabilityCStyleVariadicRule>(),
        R"cpp(
            void log(const char *fmt, ...) {}
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "portability/c-style-variadic");
}

TEST_CASE("PortabilityCStyleVariadicRuleTest.IgnoresExternCDeclaration") {
    // C-linkage functions like printf are expected to be variadic.
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PortabilityCStyleVariadicRule>(),
        R"cpp(
            extern "C" int printf(const char *, ...);
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("PortabilityCStyleVariadicRuleTest.IgnoresNonVariadicFunction") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::PortabilityCStyleVariadicRule>(),
        R"cpp(
            void log(const char *msg) {}
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── ub/virtual-call-in-ctor-dtor (CERT OOP50-CPP) ───────────────────

TEST_CASE("UbVirtualCallInCtorDtorRuleTest.DetectsVirtualCallInCtor") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbVirtualCallInCtorDtorRule>(),
        R"cpp(
            struct Base {
                virtual void init() {}
                Base() { init(); }
            };
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "ub/virtual-call-in-ctor-dtor");
}

TEST_CASE("UbVirtualCallInCtorDtorRuleTest.DetectsVirtualCallInDtor") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbVirtualCallInCtorDtorRule>(),
        R"cpp(
            struct Base {
                virtual void cleanup() {}
                ~Base() { cleanup(); }
            };
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("UbVirtualCallInCtorDtorRuleTest.IgnoresNonVirtualCall") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbVirtualCallInCtorDtorRule>(),
        R"cpp(
            struct Base {
                void setup() {}
                Base() { setup(); }
            };
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

TEST_CASE("UbVirtualCallInCtorDtorRuleTest.IgnoresVirtualCallOutsideCtorDtor") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::UbVirtualCallInCtorDtorRule>(),
        R"cpp(
            struct Base {
                virtual void init() {}
                void doInit() { init(); }
            };
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}

// ─── bugprone/narrow-wide-char-mismatch (CERT STR38-C) ───────────────

TEST_CASE("BugproneNarrowWideCharMismatchRuleTest.DetectsStrlenOnWideChar") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneNarrowWideCharMismatchRule>(),
        R"cpp(
            extern "C" unsigned long strlen(const char*);
            void test() {
                const wchar_t *ws = L"hello";
                strlen((const char*)ws);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
    CHECK(result.findings.front().ruleId == "bugprone/narrow-wide-char-mismatch");
}

TEST_CASE("BugproneNarrowWideCharMismatchRuleTest.DetectsWcslenOnNarrowChar") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneNarrowWideCharMismatchRule>(),
        R"cpp(
            extern "C" unsigned long wcslen(const wchar_t*);
            void test() {
                const char *ns = "hello";
                wcslen((const wchar_t*)ns);
            }
        )cpp");

    REQUIRE(result.success);
    REQUIRE(result.findings.size() == 1u);
}

TEST_CASE("BugproneNarrowWideCharMismatchRuleTest.IgnoresCorrectUsage") {
    const auto result = astharbor::test::runRuleOnCode(
        std::make_unique<astharbor::BugproneNarrowWideCharMismatchRule>(),
        R"cpp(
            extern "C" unsigned long strlen(const char*);
            extern "C" unsigned long wcslen(const wchar_t*);
            void test() {
                strlen("hello");
                wcslen(L"hello");
            }
        )cpp");

    REQUIRE(result.success);
    CHECK(result.findings.empty());
}
