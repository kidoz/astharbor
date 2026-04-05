# AST Matcher Cookbook

Idioms and gotchas that every ASTHarbor rule author eventually runs
into. Each entry is a problem that cost someone (a reviewer, a
debugging session, or a CI crash) to figure out the first time —
write new rules against these notes so the cost is paid once.

The entries are organized by where the gotcha bites: matcher-writing,
`run()`-time AST inspection, and test construction.

## Matchers

### Matching `std::basic_string` across inline namespaces

**Problem.** `hasName("::std::basic_string")` silently fails to match
`std::string` on macOS / Linux libc++, because libc++ wraps its types
in a `std::__1::` inline namespace. The fully-qualified name is
`::std::__1::basic_string`, not `::std::basic_string`, and Clang's
matcher name-lookup treats them as distinct identifiers despite the
`inline namespace` transparency at the language level.

**Idiom.** Drop the namespace qualifier and match by unqualified name:

```cpp
auto stringType = hasType(hasUnqualifiedDesugaredType(recordType(
    hasDeclaration(cxxRecordDecl(hasName("basic_string"))))));
```

Works on libc++ (`std::__1::basic_string`), libstdc++
(`std::__cxx11::basic_string` / plain `std::basic_string`), and MSVC
STL. Precision is fine in practice — no non-std type is named
`basic_string` in any codebase we've seen.

**Don't forget `hasUnqualifiedDesugaredType(recordType(…))`.** A bare
`hasType(cxxRecordDecl(…))` does not walk through `typedef` / `using`
aliases (`std::string` is a typedef for the templated form). The
desugaring step is what makes the matcher work on the typedef-spelled
variable as well as the templated one.

**Source:** `src/rules/performance/string_concat_in_loop.hpp`.

---

### Peeling implicit conversions off `operator=` RHS

**Problem.** `std::string s; s = s + other;` — matching the RHS of
the `operator=` as a `cxxOperatorCallExpr(+)` with
`hasArgument(1, ignoringParenImpCasts(cxxOperatorCallExpr(...)))`
silently fails to match, even though the AST clearly has the `+`
call in there.

**Why.** `operator+` returns a `std::string` **by value**. The
temporary is wrapped in `MaterializeTemporaryExpr → CXXBindTemporaryExpr`
before being passed to `operator=`. `ignoringParenImpCasts` only peels
parentheses and implicit casts, not these temporary-materialization
nodes.

**Idiom.** Use `ignoringImplicit` on arguments that cross a
by-value-return boundary:

```cpp
cxxOperatorCallExpr(
    hasOverloadedOperatorName("="),
    hasArgument(0, targetVarRef),
    hasArgument(1, ignoringImplicit(cxxOperatorCallExpr(
                       hasOverloadedOperatorName("+"),
                       hasAnyArgument(ignoringParenImpCasts(sameVarRef))))))
```

`ignoringImplicit` is the more aggressive unwrapper — it strips
`ImplicitCastExpr`, `FullExpr` (the superclass of
`ExprWithCleanups`), `MaterializeTemporaryExpr`, and
`CXXBindTemporaryExpr`. Use it at the boundary of a function return
or construction site. Inside an expression tree where everything is
lvalue, `ignoringParenImpCasts` is still the right tool and costs
less.

**Source:** `src/rules/performance/string_concat_in_loop.hpp`.

---

### Matching by direct-child vs. descendant

**Problem.** `has(declRefExpr(to(varDecl(...))))` misses matches that
seem obviously correct, because the target `DeclRefExpr` is a
**grand**child of the matched node, not a direct child. `hasDescendant`
fixes the miss but then matches things that aren't the canonical
shape (`sizeof(*p)` matching when you only wanted `sizeof(p)`).

**Idiom.** Use `has(ignoringParenImpCasts(<target>))`:

```cpp
unaryExprOrTypeTraitExpr(
    ofKind(clang::UETT_SizeOf),
    has(ignoringParenImpCasts(declRefExpr(to(varDecl(equalsBoundNode("v")))))))
```

`has()` looks at the direct child; `ignoringParenImpCasts` lets that
direct child be a `ParenExpr`-wrapped form. For `sizeof(p)` Clang
always inserts a `ParenExpr` between the `sizeof` and its operand, so
a bare `has(declRefExpr(...))` would miss. But `sizeof(*p)`'s direct
child is a `UnaryOperator(*)`, which `ignoringParenImpCasts` does not
strip — so the right shape matches and the wrong shape doesn't.

**Rule of thumb.** Reach for `hasDescendant` only when the target
genuinely can be arbitrarily deep. For a specific syntactic shape
(one identifier wrapped in parens / casts), `has + ignoringParenImpCasts`
is more precise and cheaper.

**Source:** `src/rules/bugprone/sizeof_pointer_in_memfunc.hpp`.

---

### Distinguishing decayed-array parameters from pointer locals

**Problem.** `hasType(pointerType())` on a `VarDecl` matcher does not
match this bug shape:

```cpp
void clear(char buf[256]) {
    memset(buf, 0, sizeof(buf));   // sizeof returns 8, not 256
}
```

The parameter `buf` is declared with array syntax. At the use site
inside the function it behaves as `char*` (that's the whole reason
the bug exists — `sizeof(buf)` is `sizeof(char*)`). But
`hasType(pointerType())` inspects the variable's **declared** type,
which is still `char[256]`. The matcher returns no match.

**Idiom.** Match any `VarDecl` in the matcher, then do the
pointer-vs-array discrimination in `run()`:

```cpp
// Matcher: broad
auto bufferVarRef = ignoringParenImpCasts(
    declRefExpr(to(varDecl().bind("buf_var"))));

// run(): narrow
const clang::QualType bufType = BufVar->getType();
if (bufType.isNull()) return;
const bool isParameter = llvm::isa<clang::ParmVarDecl>(BufVar);
if (!bufType->isPointerType() && !(isParameter && bufType->isArrayType())) {
    return;
}
```

The `ParmVarDecl + isArrayType()` arm catches the decayed case.
Genuine local arrays (`char buf[256]; sizeof(buf);` where
`buf` is a local, not a parameter) are correctly skipped because
`isa<ParmVarDecl>` is false and the pointer arm doesn't match
either — which is exactly what we want, because `sizeof(local_arr)`
really is the full array length.

**Source:** `src/rules/bugprone/sizeof_pointer_in_memfunc.hpp`.

---

## `run()`-time AST inspection

### Guard `QualType` dereferences with `isNull()` on templated code

**Problem.** This segfaults on self-analysis of complex template code
(e.g. ASTHarbor's own `main.cpp`, which pulls in Clang tooling
headers):

```cpp
if (lhs->getType()->isSignedIntegerType()) { return; }
```

**Why.** For dependent-type or error-recovery expressions inside
templates, `Expr::getType()` can return a `QualType` whose underlying
`Type*` is null. `QualType::operator->()` dereferences that pointer
directly without an assertion in release builds — straight to
`SIGSEGV`.

**Idiom.** Check `isNull()` first:

```cpp
const clang::QualType lhsType = lhs->getType();
if (lhsType.isNull()) { return; }
if (lhsType->isSignedIntegerType()) { return; }
```

Same rule for `VarDecl::getType()`, `Decl::getType()`, etc. If you're
going to use `operator->` on a `QualType`, `.isNull()` it first —
especially if the rule will ever run on templated code.

**Source:** `src/rules/security/integer_overflow_in_malloc.hpp`,
`src/rules/bugprone/sizeof_pointer_in_memfunc.hpp`.

---

### Constant-folding: prefer `EvaluateAsInt` over `isIntegerConstantExpr`

**Problem.** To skip a rule when an operand is a compile-time
constant, two APIs look equivalent:

```cpp
if (lhs->isIntegerConstantExpr(*Result.Context)) { … }   // option A
```

```cpp
clang::Expr::EvalResult eval;
if (lhs->EvaluateAsInt(eval, *Result.Context)) { … }     // option B
```

Both work. But the codebase has converged on **option B** (see
`ub/shift_past_bitwidth.hpp`, `ub/implicit_widening_multiplication.hpp`,
`ub/static_array_oob_constant.hpp`, `ub/shift_by_negative.hpp`, and
now `security/integer_overflow_in_malloc.hpp`). `EvaluateAsInt` is
non-deprecated, writes to a caller-provided `EvalResult` (no
optional wrapping), and matches the `Expr::EvaluateAs*` family
convention.

---

### Classifying an operand as "signed user input" vs "signed constant"

**Problem.** A filter like "skip if an operand has signed integer
type" is too coarse. `malloc(unsigned_n * 4)` silently passes
because the `4` literal has type `int` (signed by default) — but the
multiplication is effectively unsigned at runtime (the unsigned
operand dominates per C conversion rules), and the rule should catch
the unsigned-overflow case.

**Idiom.** Combine the type check with a constant check. Skip only
when a **non-constant** operand has the unwanted type:

```cpp
clang::Expr::EvalResult lhsEval;
clang::Expr::EvalResult rhsEval;
const bool lhsConstant = lhs->EvaluateAsInt(lhsEval, *Result.Context);
const bool rhsConstant = rhs->EvaluateAsInt(rhsEval, *Result.Context);
if (lhsConstant && rhsConstant) { return; }  // compile-time folded

if ((!lhsConstant && lhsType->isSignedIntegerType()) ||
    (!rhsConstant && rhsType->isSignedIntegerType())) {
    return;   // non-constant signed operand → owned by another rule
}
```

The classification "non-constant signed" is what distinguishes
"user-controlled signed input" from "a literal whose type happens to
be signed".

**Source:** `src/rules/security/integer_overflow_in_malloc.hpp`.

---

### Emitting canonical file paths

ASTHarbor rules don't need to touch file-path canonicalization
directly — the `Rule::makeFinding` / `Rule::emitFinding` helpers in
`include/astharbor/rule.hpp` already walk through
`FileEntry::tryGetRealPathName` → `FileManager::getCanonicalName` →
`FileEntryRef::getName` to produce an absolute real-path string.

Additionally, the `MatchFinderWithDepsAction` in
`src/cli/dependency_collector.hpp` records every short-name →
real-path alias it sees during preprocessing, and `runAnalysisChunk`
applies the map to every `finding.file` after `tool.run()`. Net
result: `finding.file` is always a canonical absolute path, even for
rules that bypass `makeFinding` and construct `Finding` manually.

**Don't** hand-roll path canonicalization in a new rule. Use
`emitFinding` and let the infrastructure do it.

---

## CFG-based rules

### Reuse the shared CFG helpers

`include/astharbor/cfg_reachability.hpp` exposes the primitives every
CFG-based rule needs:

| Helper | Use for |
| --- | --- |
| `cfg::getOrBuildCfg(func, ctx)` | thread-local cached CFG per function |
| `cfg::locateStmt(cfg, stmt)` | find `(block, index)` containing a given `Stmt*` |
| `cfg::locateDecl(cfg, var)` | find `(block, index)` containing a given `VarDecl` |
| `cfg::locateTerminator(cfg, stmt)` | find the `CFGBlock` whose terminator is a given control-flow stmt |
| `cfg::forwardReachable(block, index, stopsPath, findsReport)` | BFS over successor blocks with per-element predicate callbacks |
| `cfg::isAssignmentTo(stmt, var)` / `cfg::isDeleteOf(stmt, var)` | common path-terminator predicates |
| `cfg::isDirectRefTo(expr, var)` | strip parens+casts, test for `DeclRefExpr` to `var` |
| `cfg::findFirstDescendantIf(stmt, pred)` / `cfg::findFirstDescendant<T>(stmt)` | generic subtree search, return first matching node |
| `cfg::functionHasTryBlock(func)` | memoized "does this function contain a `try`?" |
| `cfg::clearCfgCache()` | end-of-TU cleanup (the dep collector does this automatically for CLI runs) |

A new CFG rule's `run()` should be ~25 lines of glue around these
helpers. See `src/rules/ub/use_after_move.hpp` as the reference
template, or `src/rules/resource/leak_on_throw.hpp` for a rule that
also gates on `functionHasTryBlock`.

### Clear the cache at end-of-TU

If you're writing a new test harness or frontend action that runs a
CFG rule, you **must** call `cfg::clearCfgCache()` at end-of-TU.
`FunctionDecl*` keys are only valid within one `ASTContext`; leaving
stale entries risks use-after-free on pointer aliasing into the next
TU. The existing plumbing that handles this:

- `src/cli/dependency_collector.hpp` — `MatchFinderWithDepsAction::EndSourceFileAction`
- `tests/unit/rule_test_utils.hpp` — `runRuleOnCode`

---

## Tests

### Test harness invariants

`tests/unit/rule_test_utils.hpp::runRuleOnCode` is the one helper for
every rule test:

```cpp
const auto result = astharbor::test::runRuleOnCode(
    std::make_unique<MyRule>(),
    R"cpp(
        // ... test snippet ...
    )cpp");

REQUIRE(result.success);
REQUIRE(result.findings.size() == 1u);
CHECK(result.findings.front().ruleId == "my/rule-id");
```

**Asserting `result.success`** at the start of every test is
important because the helper runs the Clang frontend on the snippet;
if the snippet fails to compile, the matcher never runs and a "no
findings" assertion would silently pass for the wrong reason.

### Work around Clang's reference-to-local hard error

Clang errors out (not warns) on `int& f() { int x; return x; }` —
the parser emits "non-const lvalue reference to type 'int' cannot
bind to a temporary". This kills any test that tries to exercise
that exact pattern because the test snippet won't compile and
`result.success` is `false`.

**Workaround.** Use `const int&` in the test snippet. The matcher
for `ub/dangling-reference` uses `returns(referenceType())`, which
matches const and non-const references alike, so the test still
exercises the rule:

```cpp
R"cpp(
    const int& test() {
        int x = 42;
        return x;
    }
)cpp"
```

**Source:** `tests/unit/test_rules.cpp` — `UbDanglingReferenceRuleTest`.

### Using `-Wno-error=...` in tests

If a snippet must include code that Clang warns on (e.g. the
dangling-reference tests above), you'll see warnings in the test
output but the test will pass. That's fine. Only a hard error would
set `result.success = false`.
