# Rules

ASTHarbor currently ships local, deterministic AST matcher rules in the same broad families used by `clang-tidy`: `bugprone`, `modernize`, `performance`, `readability`, and `security`.

> **Writing a new rule?** Start with [matcher-cookbook.md](matcher-cookbook.md) — it captures the non-obvious Clang AST matcher idioms (inline-namespace type matching, decayed-array parameters, null `QualType` guards, CFG helpers, etc.) that every rule author eventually runs into.

## Current Rules

| Rule ID | What it detects | Comparable check |
| --- | --- |
| `modernize/use-nullptr` | `NULL` used where `nullptr` should be used. | `clang-tidy` `modernize-use-nullptr` |
| `modernize/use-override` | Overriding virtual methods that do not spell the `override` keyword. | `clang-tidy` `modernize-use-override` |
| `bugprone/assignment-in-condition` | Assignments used directly inside `if`/`while`/`do`/`for` conditions. | `clang-tidy` `bugprone-assignment-in-if-condition` |
| `bugprone/identical-expressions` | The same variable referenced on both sides of a comparison or arithmetic operator. | Similar to `clang-tidy` / PVS expression sanity checks |
| `bugprone/suspicious-memset` | `memset` where the size argument is `sizeof(pointer)`. | Similar to `clang-tidy` `bugprone-sizeof-expression` / memory-misuse checks |
| `bugprone/suspicious-semicolon` | `if` statements whose body is only a stray semicolon. | `clang-tidy` `bugprone-suspicious-semicolon` |
| `bugprone/unsafe-memory-operation` | `memset`/`memcpy`/`memmove` on non-trivially-copyable objects. | `clang-tidy` `bugprone-undefined-memory-manipulation` |
| `performance/for-loop-copy` | Range-for loop variables that copy record types instead of using a reference. | `clang-tidy` `performance-for-range-copy` |
| `readability/container-size-empty` | Container `size()` checks against zero instead of `empty()`. | `clang-tidy` `readability-container-size-empty` |
| `readability/const-return-type` | Functions returning `const` value types that inhibit moves. | `clang-tidy` `readability-const-return-type` |
| `security/no-gets` | Calls to `gets()`, which has no bounds checking and was removed from C11. | CERT-C MSC24-C, CWE-120 |
| `security/unsafe-temp-file` | Calls to `tmpnam()`, `tempnam()`, `mktemp()` — predictable/race-prone temp files. | CERT-C FIO21-C, CWE-377 |
| `security/unsafe-printf-format` | Non-literal format string in `printf`-family calls. | CERT-C FIO30-C, CWE-134 |
| `security/no-sprintf` | Calls to `sprintf()` which performs unbounded writes. | CERT-C MSC24-C, CWE-120 |
| `security/no-strcpy-strcat` | Calls to `strcpy()`, `strcat()`, `wcscpy()`, `wcscat()` — unbounded string copies. | CERT-C STR31-C, CWE-120 |
| `security/unchecked-realloc` | `p = realloc(p, n)` pattern that leaks on failure. | CERT-C MEM04-C, CWE-401 |
| `security/no-system-call` | Calls to `system()` — command injection risk. | CERT-C ENV33-C, CWE-78 |
| `security/no-atoi-atol-atof` | Calls to `atoi()`, `atol()`, `atoll()`, `atof()` — no error distinction. | CERT-C ERR07-C, CWE-20 |
| `security/deprecated-crypto-call` | Calls to weak crypto APIs: MD5, SHA1, RC4, DES. | CERT-C MSC41-C, CWE-327 |
| `security/no-alloca` | Calls to `alloca()` — stack allocation with no overflow protection. | CERT-C MEM05-C, CWE-770 |
| `security/no-signal` | Calls to `signal()` instead of `sigaction()`. | CERT-C SIG34-C, CWE-364 |
| `security/no-rand` | Calls to `rand()`, `srand()`, `random()` — weak PRNGs. | CERT-C MSC30-C, CWE-338 |
| `security/missing-return-value-check` | Privilege-dropping calls (`setuid`/`setgid`) with unchecked return value. | CERT-C POS36-C, CWE-273 |
| `security/no-scanf-without-width` | `scanf`-family with bare `%s` (no field width) — buffer overflow risk. | CERT-C MSC24-C, CWE-120 |
| `security/signed-arith-in-alloc` | Signed integer arithmetic used as allocation size argument. | CERT-C INT32-C, CWE-190 |
| `security/large-stack-array` | Local fixed-size arrays exceeding 4096 bytes — stack overflow risk. | CERT-C MEM05-C, CWE-121 |
| `security/integer-signedness-mismatch` | Comparisons between signed and unsigned integer types. | CERT-C INT02-C, CWE-195 |

## Similar Tools And What They Detect

### [`clang-tidy`](https://clang.llvm.org/extra/clang-tidy/)

- Best comparison point for ASTHarbor today.
- Strong at local semantic checks driven by the Clang AST: modernization, readability, performance, suspicious conditions, memory API misuse, and many targeted bug-prone patterns.
- ASTHarbor’s current rule model is intentionally closest to this tool family.

### [`Cppcheck`](https://cppcheck.sourceforge.io/)

- Goes beyond simple local matchers into broader bug finding such as null dereference, uninitialized variables, bounds issues, leaks, and dead code.
- Also supports addons for secure coding standards and policy-style checking.
- The official project overview calls out undefined behavior checks including dead pointers, division by zero, integer overflows, invalid conversions, memory management, null pointer dereferences, out-of-bounds access, and uninitialized variables.

### [`PVS-Studio`](https://pvs-studio.com/en/docs/warnings/)

- Much broader diagnostic catalog, including undefined behavior, 64-bit portability, optimization issues, MISRA/CERT/OWASP style mappings, and security-oriented findings.
- Good reference for future category expansion, but much of that surface requires heavier dataflow or domain-specific modeling than ASTHarbor currently has.

### [`Infer`](https://fbinfer.com/)

- Interprocedural analyzer focused on deeper program reasoning.
- Especially strong for null dereference, resource leaks, and concurrency issues, which are outside ASTHarbor’s current matcher-only MVP.
- Infer’s published checker families cover interprocedural memory safety (`Pulse`), legacy leak/null analyses (`Biabduction`), taint analysis (`Quandary` / Pulse), and data race detection (`RacerD`).

## Practical Positioning

- Use ASTHarbor for fast, deterministic, Clang-first local diagnostics.
- Treat `clang-tidy` as the closest functional benchmark for short-term rule growth.
- Treat `Cppcheck`, `PVS-Studio`, and `Infer` as references for longer-term dataflow, security, and interprocedural roadmap work rather than parity targets for the current architecture.

## Research References

- `clang-tidy` checks referenced while expanding ASTHarbor:
  [bugprone-assignment-in-if-condition](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/assignment-in-if-condition.html),
  [bugprone-suspicious-semicolon](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/suspicious-semicolon.html),
  [bugprone-undefined-memory-manipulation](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/undefined-memory-manipulation.html)
- `Cppcheck` capability overview:
  [project homepage](https://cppcheck.sourceforge.io/),
  [manual](https://cppcheck.sourceforge.io/manual.html)
- `PVS-Studio` catalog and capability matrix:
  [warning catalog](https://pvs-studio.com/en/docs/warnings/)
- `Infer` overview and checker families:
  [about Infer](https://fbinfer.com/docs/about-Infer/),
  [Pulse](https://fbinfer.com/docs/1.1.0/checker-pulse/),
  [Biabduction](https://fbinfer.com/docs/checker-biabduction/),
  [RacerD](https://fbinfer.com/docs/checker-racerd/),
  [Quandary](https://fbinfer.com/docs/checker-quandary/)

## Adding A New Rule

Add new rules by implementing `astharbor::Rule`, registering matchers with `clang::ast_matchers::MatchFinder`, and registering the rule in `src/core/rule_registry.cpp`.
