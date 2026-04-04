#include "astharbor/rule_registry.hpp"
#include "../rules/bugprone/assignment_in_condition.hpp"
#include "../rules/bugprone/identical_expressions.hpp"
#include "../rules/bugprone/suspicious_memset.hpp"
#include "../rules/bugprone/suspicious_semicolon.hpp"
#include "../rules/bugprone/unsafe_memory_operation.hpp"
#include "../rules/modernize/use_nullptr.hpp"
#include "../rules/modernize/use_override.hpp"
#include "../rules/performance/for_loop_copy.hpp"
#include "../rules/readability/const_return_type.hpp"
#include "../rules/readability/container_size_empty.hpp"
#include "../rules/security/no_gets.hpp"
#include "../rules/security/unsafe_temp_file.hpp"
#include "../rules/security/unsafe_printf_format.hpp"
#include "../rules/security/no_sprintf.hpp"
#include "../rules/security/no_strcpy_strcat.hpp"
#include "../rules/security/unchecked_realloc.hpp"
#include "../rules/security/no_system_call.hpp"
#include "../rules/security/no_atoi.hpp"
#include "../rules/security/deprecated_crypto_call.hpp"
#include "../rules/security/no_alloca.hpp"
#include "../rules/security/no_signal.hpp"
#include "../rules/security/no_rand.hpp"
#include "../rules/security/missing_return_value_check.hpp"
#include "../rules/security/no_scanf_without_width.hpp"
#include "../rules/security/signed_arith_in_alloc.hpp"
#include "../rules/security/large_stack_array.hpp"
#include "../rules/security/integer_signedness_mismatch.hpp"

namespace astharbor {

void registerBuiltinRules(RuleRegistry& registry) {
    registry.registerRule(std::make_unique<ModernizeUseNullptrRule>());
    registry.registerRule(std::make_unique<ModernizeUseOverrideRule>());
    registry.registerRule(std::make_unique<BugproneAssignmentInConditionRule>());
    registry.registerRule(std::make_unique<ReadabilityConstReturnTypeRule>());
    registry.registerRule(std::make_unique<PerformanceForLoopCopyRule>());
    registry.registerRule(std::make_unique<ReadabilityContainerSizeEmptyRule>());
    registry.registerRule(std::make_unique<BugproneIdenticalExpressionsRule>());
    registry.registerRule(std::make_unique<BugproneSuspiciousMemsetRule>());
    registry.registerRule(std::make_unique<BugproneSuspiciousSemicolonRule>());
    registry.registerRule(std::make_unique<BugproneUnsafeMemoryOperationRule>());
    registry.registerRule(std::make_unique<SecurityNoGetsRule>());
    registry.registerRule(std::make_unique<SecurityUnsafeTempFileRule>());
    registry.registerRule(std::make_unique<SecurityUnsafePrintfFormatRule>());
    registry.registerRule(std::make_unique<SecurityNoSprintfRule>());
    registry.registerRule(std::make_unique<SecurityNoStrcpyStrcatRule>());
    registry.registerRule(std::make_unique<SecurityUncheckedReallocRule>());
    registry.registerRule(std::make_unique<SecurityNoSystemCallRule>());
    registry.registerRule(std::make_unique<SecurityNoAtoiRule>());
    registry.registerRule(std::make_unique<SecurityDeprecatedCryptoCallRule>());
    registry.registerRule(std::make_unique<SecurityNoAllocaRule>());
    registry.registerRule(std::make_unique<SecurityNoSignalRule>());
    registry.registerRule(std::make_unique<SecurityNoRandRule>());
    registry.registerRule(std::make_unique<SecurityMissingReturnValueCheckRule>());
    registry.registerRule(std::make_unique<SecurityNoScanfWithoutWidthRule>());
    registry.registerRule(std::make_unique<SecuritySignedArithInAllocRule>());
    registry.registerRule(std::make_unique<SecurityLargeStackArrayRule>());
    registry.registerRule(std::make_unique<SecurityIntegerSignednessMismatchRule>());
}

} // namespace astharbor
