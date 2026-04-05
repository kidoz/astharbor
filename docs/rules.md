# Rules

ASTHarbor currently ships local, deterministic AST matcher rules in the same broad families used by `clang-tidy`: `bugprone`, `modernize`, `performance`, `readability`, and `security`.

> **Writing a new rule?** Start with [matcher-cookbook.md](matcher-cookbook.md) — it captures the non-obvious Clang AST matcher idioms (inline-namespace type matching, decayed-array parameters, null `QualType` guards, CFG helpers, etc.) that every rule author eventually runs into.

## Current Rules

Rules are grouped by category. Tier 2 rules use CFG-based dataflow
(`include/astharbor/cfg_reachability.hpp`); everything else is a
pure AST matcher.

### `ub/` — Undefined behavior

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `ub/c-style-cast-pointer-punning` | C-style cast reinterpreting a pointer between unrelated types. | MISRA C 11.3, CERT EXP39-C |
| `ub/casting-through-void` | `reinterpret_cast` routed through `void*` to launder a pointer. | CERT EXP36-C |
| `ub/dangling-reference` | Returning a reference / address to a local whose storage ends at return. | CERT DCL30-C, CWE-562 |
| `ub/delete-non-virtual-dtor` | `delete` through a base pointer whose class has no virtual destructor. | CERT OOP52-CPP, CWE-1079 |
| `ub/division-by-zero-literal` | Division or modulo by a compile-time zero literal. | CERT INT33-C, CWE-369 |
| `ub/double-free-local` | **(CFG)** Same local pointer passed to `delete` twice without reassignment. | CERT MEM30-C, CWE-415 |
| `ub/free-of-non-heap` | `free()` called on a stack variable, static/global, array, or string literal. | CERT MEM34-C, CWE-590 |
| `ub/implicit-widening-multiplication` | Narrow-typed multiplication whose result is then widened — overflow before the widen. | CERT INT18-C, CWE-190 |
| `ub/missing-return-in-non-void` | Non-`void` function with a control-flow path that exits without `return`. | CERT MSC37-C, CWE-758 |
| `ub/move-of-const` | `std::move` on a `const` lvalue — silently produces a copy, not a move. | `clang-tidy` `performance-move-const-arg` |
| `ub/new-delete-array-mismatch` | `delete` paired with `new[]` or `delete[]` paired with `new`. | CERT MEM51-CPP, CWE-762 |
| `ub/noreturn-function-returns` | A `[[noreturn]]` function with a control-flow path that can return. | CERT MSC53-CPP |
| `ub/null-deref-after-check` | **(CFG)** Pointer dereferenced inside the then-branch of a null check. | CERT EXP34-C, CWE-476 |
| `ub/pointer-arithmetic-on-polymorphic` | Array subscripting / pointer arithmetic on a pointer-to-base type. | CERT CTR56-CPP, CWE-843 |
| `ub/reinterpret-cast-type-punning` | `reinterpret_cast` between unrelated object types — strict-aliasing violation. | CERT EXP39-C, CWE-843 |
| `ub/shift-by-negative` | Left/right shift by a negative compile-time constant. | CERT INT34-C, CWE-1335 |
| `ub/shift-past-bitwidth` | Shift whose RHS is ≥ the LHS bit width (compile-time constant). | CERT INT34-C, CWE-1335 |
| `ub/sizeof-array-parameter` | `sizeof(parm)` where `parm` is a decayed array parameter — returns pointer size. | CERT EXP01-C |
| `ub/static-array-oob-constant` | Constant array index that is outside the declared bounds. | CERT ARR30-C, CWE-125 |
| `ub/uninitialized-local` | **(CFG)** Read of a local scalar reachable on a path with no prior write. | CERT EXP33-C, CWE-457 |
| `ub/use-after-free` | **(CFG)** Dereference / call-arg use of a local pointer after `free()` with no reassignment. | CERT MEM30-C, CWE-416 |
| `ub/use-after-move` | **(CFG)** Use of a local variable after `std::move` with no intervening reassignment. | `clang-tidy` `bugprone-use-after-move` |

### `security/` — Security and CWE-mapped

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `security/deprecated-crypto-call` | Calls to weak crypto APIs: MD5, SHA1, RC4, DES. | CERT MSC41-C, CWE-327 |
| `security/integer-overflow-in-malloc` | `malloc`/`realloc` size argument is an unsigned multiplication that can wrap. | CERT INT30-C, CWE-190 |
| `security/integer-signedness-mismatch` | Comparisons between signed and unsigned integer types. | CERT INT02-C, CWE-195 |
| `security/large-stack-array` | Local fixed-size arrays exceeding 4096 bytes. | CERT MEM05-C, CWE-121 |
| `security/missing-return-value-check` | Privilege-dropping calls (`setuid`/`setgid`) with unchecked return value. | CERT POS36-C, CWE-273 |
| `security/no-alloca` | Calls to `alloca()` — unbounded stack allocation. | CERT MEM05-C, CWE-770 |
| `security/no-atoi-atol-atof` | `atoi`/`atol`/`atoll`/`atof` — no way to distinguish errors from valid zero. | CERT ERR07-C, CWE-20 |
| `security/no-gets` | `gets()` — unbounded read, removed from C11. | CERT MSC24-C, CWE-120 |
| `security/no-rand` | `rand`/`srand`/`random` — cryptographically weak PRNGs. | CERT MSC30-C, CWE-338 |
| `security/no-scanf-without-width` | `scanf`-family with bare `%s` (no field width). | CERT MSC24-C, CWE-120 |
| `security/no-signal` | Calls to `signal()` instead of `sigaction()`. | CERT SIG34-C, CWE-364 |
| `security/no-sprintf` | `sprintf()` — unbounded writes. | CERT MSC24-C, CWE-120 |
| `security/no-strcpy-strcat` | `strcpy`/`strcat`/`wcscpy`/`wcscat` — unbounded string copies. | CERT STR31-C, CWE-120 |
| `security/no-system-call` | `system()` — command injection risk. | CERT ENV33-C, CWE-78 |
| `security/signed-arith-in-alloc` | Signed integer arithmetic (`+`/`-`/`*`) used as allocation size. | CERT INT32-C, CWE-190 |
| `security/unchecked-realloc` | `p = realloc(p, n)` leaks `p` on allocation failure. | CERT MEM04-C, CWE-401 |
| `security/unsafe-printf-format` | Non-literal format string in `printf`-family calls. | CERT FIO30-C, CWE-134 |
| `security/unsafe-temp-file` | `tmpnam`/`tempnam`/`mktemp` — predictable / race-prone temp files. | CERT FIO21-C, CWE-377 |

### `bugprone/` — Suspicious patterns and common mistakes

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `bugprone/assignment-in-condition` | Assignments used inside `if`/`while`/`do`/`for` conditions. | CERT EXP45-C, `clang-tidy` `bugprone-assignment-in-if-condition` |
| `bugprone/char-eof-comparison` | `getchar`/`getc`/`fgetc` return narrowed to `char` — loses EOF sentinel. | CERT FIO34-C, CWE-197 |
| `bugprone/identical-expressions` | The same variable on both sides of a comparison or arithmetic operator. | PVS-like expression sanity check |
| `bugprone/sizeof-pointer-in-memfunc` | `memcpy`/`memmove`/etc. with `sizeof(ptr)` for the length. | CERT EXP01-C, CWE-467 |
| `bugprone/suspicious-memset` | `memset` with `sizeof(pointer)` as the size. | `clang-tidy` `bugprone-sizeof-expression` |
| `bugprone/suspicious-semicolon` | `if` statement whose body is only a stray `;`. | `clang-tidy` `bugprone-suspicious-semicolon` |
| `bugprone/swapped-arguments` | Argument variable names cross-match the callee's parameter names. | `clang-tidy` `readability-named-parameter`-adjacent |
| `bugprone/unsafe-memory-operation` | `memset`/`memcpy`/`memmove` on non-trivially-copyable objects. | `clang-tidy` `bugprone-undefined-memory-manipulation` |

### `resource/` — RAII / ownership

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `resource/leak-on-throw` | **(CFG)** Raw-new'd local pointer not deleted before a reachable `throw`. | CERT MEM31-C, CWE-401 |

### `modernize/` — Modernization

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `modernize/use-nullptr` | `NULL` or `0` used where `nullptr` should be used. | `clang-tidy` `modernize-use-nullptr` |
| `modernize/use-override` | Overriding virtual methods that don't spell the `override` keyword. | `clang-tidy` `modernize-use-override` |

### `performance/`

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `performance/for-loop-copy` | Range-for loop variables copying record types instead of binding a reference. | `clang-tidy` `performance-for-range-copy` |
| `performance/string-concat-in-loop` | `s = s + other` on a `std::basic_string` inside a loop — quadratic. | `clang-tidy` `performance-inefficient-string-concatenation` |

### `readability/`

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `readability/const-return-type` | Functions returning `const` value types that inhibit moves. | `clang-tidy` `readability-const-return-type` |
| `readability/container-size-empty` | Container `size()` compared to zero instead of `empty()`. | `clang-tidy` `readability-container-size-empty` |
| `readability/use-using-alias` | `typedef` used where a C++11 `using` alias is clearer. | `clang-tidy` `modernize-use-using` |

### `portability/`

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `portability/c-style-variadic` | C-style variadic function definition (`void f(int, ...)`) — use templates. | CERT DCL50-CPP |
| `portability/vla-in-cxx` | Variable-length arrays in C++ — not portable, not in ISO C++. | `clang-tidy` `cppcoreguidelines-avoid-c-arrays` |

### `best-practice/`

| Rule ID | What it detects | Reference |
| --- | --- | --- |
| `best-practice/explicit-single-arg-ctor` | Single-argument constructors not marked `explicit`. | `clang-tidy` `google-explicit-constructor` |
| `best-practice/no-raw-new-delete` | Raw `new`/`delete` in user code — prefer smart pointers. | `clang-tidy` `cppcoreguidelines-owning-memory` |

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
