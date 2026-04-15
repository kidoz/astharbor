# Architecture

## High-Level Overview

ASTHarbor is a C/C++ static analyzer built on Clang LibTooling. It has two
frontends — a native CLI and a Python MCP server — layered on top of a
single core analysis library.

```
                          +----------------------+
                          |   User / IDE / AI    |
                          +----------+-----------+
                                     |
                  +------------------+------------------+
                  |                                     |
         +--------v--------+                  +---------v--------+
         |   CLI Frontend  |                  |   MCP Frontend   |
         |   (C++ binary)  |                  | (Python/FastMCP) |
         +--------+--------+                  +---------+--------+
                  |                                     |
                  |                           subprocess invocation
                  |                                     |
                  +------------------+------------------+
                                     |
                          +----------v-----------+
                          | Core Analyzer Library |
                          |    (libastharbor)    |
                          +----------+-----------+
                                     |
       +-----------+-----------+-----+-----+-----------+-----------+
       |           |           |           |           |           |
  +----v----+ +----v----+ +----v----+ +----v----+ +----v----+ +----v----+
  |  Rule   | | Analyzer| | Compile |  Emitters | |   Fix   | |  Run    |
  | Registry| | driver  | | Database| |text/json | |Applicator| |  Store  |
  |         | |         | | handling| |  /sarif  | |          | |         |
  +---------+ +---------+ +---------+ +----------+ +----------+ +---------+
       |
  +----v-------------+
  | AST Matcher Rules |
  |  (~46 built-in,   |
  |   8 categories)   |
  +-------------------+
```

## Core Analyzer Library (C++23)

The core compiles into a static library (`libastharbor`) using Meson and
links against `libclang-cpp`. It requires LLVM >= 14 and the C++23 standard.

### Rule registry and rule base class

- `RuleRegistry` (`include/astharbor/rule_registry.hpp`) owns a vector of
  `std::unique_ptr<Rule>`. The free function `registerBuiltinRules()` in
  `src/core/rule_registry.cpp` populates it with every shipped rule.
- Every rule inherits from `Rule` (`include/astharbor/rule.hpp`), which
  itself extends `clang::ast_matchers::MatchFinder::MatchCallback`. Rules
  implement `id()`, `title()`, `category()`, `summary()`,
  `defaultSeverity()`, `registerMatchers()`, and `run()`.
- The base class provides helpers that remove boilerplate from the ~46
  concrete rules:
  - `isInSystemHeader()` filters out noise from system headers.
  - `makeFinding()` builds a `Finding` pre-populated with rule metadata and
    a decomposed source location, returning `std::nullopt` when the match
    should be suppressed.
  - `emitFinding()` is a convenience wrapper that pushes the result onto
    the rule's internal `findings` vector.
  - `nextFixId()` generates a monotonic per-rule fix id.

### Shipped rules

~46 rules across eight categories:

| Category       | Examples                                                                                                                                          |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `bugprone`     | assignment-in-condition, identical-expressions, suspicious-memset, suspicious-semicolon, unsafe-memory-operation                                  |
| `modernize`    | use-nullptr, use-override                                                                                                                          |
| `performance`  | for-loop-copy                                                                                                                                      |
| `readability`  | const-return-type, container-size-empty, use-using-alias                                                                                           |
| `security`     | no-gets, no-sprintf, no-strcpy-strcat, unsafe-printf-format, unsafe-temp-file, unchecked-realloc, no-system-call, no-atoi, deprecated-crypto-call, no-alloca, no-signal, no-rand, missing-return-value-check, no-scanf-without-width, signed-arith-in-alloc, large-stack-array, integer-signedness-mismatch |
| `ub`           | missing-return-in-non-void, division-by-zero-literal, shift-by-negative, shift-past-bitwidth, static-array-oob-constant, delete-non-virtual-dtor, new-delete-array-mismatch, pointer-arithmetic-on-polymorphic, implicit-widening-multiplication, noreturn-function-returns, reinterpret-cast-type-punning, c-style-cast-pointer-punning, casting-through-void, move-of-const, sizeof-array-parameter |
| `portability`  | vla-in-cxx                                                                                                                                         |
| `best-practice`| no-raw-new-delete, explicit-single-arg-ctor                                                                                                        |

### Finding, Fix, and AnalysisResult

```cpp
struct Fix {
    std::string fixId;
    std::string description;
    std::string safety;           // "safe" | "review" | "manual"
    std::string replacementText;
    int offset = 0;
    int length = 0;
};

struct Finding {
    std::string findingId;
    std::string ruleId;
    std::string severity;
    std::string message;
    std::string category;
    std::string file;
    int line = 0;
    int column = 0;
    std::vector<Fix> fixes;
};

struct AnalysisResult {
    std::string runId;
    bool success = true;
    std::vector<Finding> findings;
};
```

`generateRunId()` (in `include/astharbor/analyzer.hpp`) stamps a run id of
the form `run-<hex-millis>`. `assignFindingIds()` walks the final findings
vector and assigns sequential ids (`finding-0000`, `finding-0001`, …) so the
same finding stays addressable across runs that start from an identical
source base.

### Compilation database handling

`CompilationDB` (`include/astharbor/compilation_db.hpp`) wraps Clang's
`CompilationDatabase`. When analyzing files, the CLI delegates to
`CommonOptionsParser`, which walks upward from the current directory looking
for `compile_commands.json`. If no sources are specified explicitly, the
tool applies a source-selection policy before invoking Clang. For Meson
builds, `--source-scope=auto` uses `meson-info/intro-targets.json` and
`intro-tests.json` to select root project non-test targets, which keeps
wrapped dependencies out of ordinary project scans. `--source-scope=project`
includes root tests, and `--source-scope=all` falls back to every entry in
the compilation database.

### Emitters

Emitters implement `IEmitter` (`include/astharbor/emitter.hpp`), which has a
single `emit(const AnalysisResult &, std::ostream &)` method. Three shipped
implementations:

- `TextEmitter` (`src/emitters/text_emitter.cpp`) — Clang-style
  `file:line:col: <severity>: message [rule-id]` output.
- `JsonEmitter` (`src/emitters/json_emitter.cpp`) — Structured JSON
  containing `runId`, `success`, and a `findings` array with fixes.
- `SarifEmitter` (`src/emitters/sarif_emitter.cpp`) — SARIF 2.1.0. The
  emitter takes a `RuleRegistry*` so it can populate `tool.driver.rules`
  with full rule metadata, map severity strings to SARIF levels, index each
  result back to its rule via `ruleIndex`, and encode fixes into the SARIF
  `fixes[]`/`artifactChanges[]`/`replacements[]` structure.

### Fix applicator

`FixApplicator` (`include/astharbor/fix_applicator.hpp`) is a static helper
with two entry points:

- `preview(findings, ostream)` — prints a per-file human-readable summary.
- `apply(findings, backup)` — reads each affected file, optionally writes a
  `.bak`, sorts fixes by offset descending, applies replacements end-to-
  beginning (to keep offsets stable), writes the result, and returns an
  `ApplyResult{ filesModified, fixesApplied, fixesSkipped, errors }`. Only
  fixes labeled `"safe"` are written; `"review"` and `"manual"` fixes are
  skipped and counted.

### Run store

`RunStore` (`include/astharbor/run_store.hpp`) persists an `AnalysisResult`
as `llvm::json` under `~/.astharbor/runs/<runId>.json` (or an explicit path
supplied via `--save-run=PATH`). `RunStore::load()` reads a saved run back
into an `AnalysisResult` so `astharbor fix --run-id` can operate on it
without re-running Clang.

## CLI Frontend

`src/cli/main.cpp` is a standalone executable linked against
`libastharbor`. It uses LLVM's `cl::opt` CommandLine library for option
parsing and Clang's `CommonOptionsParser` for source-file and compilation-
database resolution.

Subcommands and their responsibilities:

| Command   | Purpose                                                         |
|-----------|-----------------------------------------------------------------|
| `analyze` | Resolve sources → run analysis (optionally parallel) → emit     |
| `fix`     | Produce or load an `AnalysisResult` → preview or apply fixes    |
| `rules`   | Dump the contents of `RuleRegistry` (text or JSON)             |
| `doctor`  | Print rule count and compilation-database availability         |
| `compare` | Call `clang++`/`g++` `-fsyntax-only` on a single file and diff diagnostics counts |

Option wiring lives at module scope in `main.cpp`:

- `Format`, `Apply`, `DryRun`, `RuleFilter`, `Backup`
- `SaveRun`, `RunId`, `FindingId`
- `Checks`, `Verbose`, `Std`, `CompilerProfile`, `Jobs`, `ChangedOnly`

The `runAnalysis()` helper is shared between `analyze` and `fix`: it honors
`--changed-only` (intersecting sources with `git diff`), `--checks`
(per-rule include/exclude substring patterns), `--std` and
`--compiler-profile` (via `ArgumentsAdjuster`), `--verbose` (progress +
timing on stderr), and `--jobs` (round-robin partitioning of sources into
N worker threads, each with a fresh `RuleRegistry` and `ClangTool`,
with findings merged and sorted deterministically by
`(file, line, column, ruleId)` after all workers finish).

See [cli.md](cli.md) for the full command reference.

## MCP Frontend (Python)

`python/astharbor_mcp/` is a FastMCP server. It never links Clang; every
tool invocation spawns the `astharbor` binary via `subprocess.run()` and
parses the resulting stdout.

Modules:

- `server.py` — declares the FastMCP instance and all tools/resources.
- `cli_bridge.py` — locates the native binary (PATH + build-directory
  fallback) and wraps every CLI subcommand with a Python function.
- `models.py` — Pydantic v2 models (`Fix`, `Finding`, `AnalysisResult`,
  `ApplyResult`) with camelCase aliases so both `result["runId"]` and
  `result.run_id` round-trip.
- `resources.py` — an LRU `RunCache` (20 runs max) plus the MCP resources
  that surface it.
- `tasks.py` — `TaskManager` + daemon-thread workers used by the
  `start_background_analysis` / `get_task_status` / `get_task_result` /
  `list_background_tasks` tools.

See [mcp.md](mcp.md) for the tool/resource catalog.

## Data Flow

### Analysis flow

```
Source files (*.cpp, *.c)
        |
        v
CommonOptionsParser (resolves compile_commands.json)
        |
        v
(optional) --changed-only filter via `git diff --name-only`
        |
        v
runAnalysis() chooses sequential or N-worker round-robin partitioning
        |
        v
For each chunk: fresh RuleRegistry, ClangTool, MatchFinder
        |
        v
Clang LibTooling drives AST parsing for each translation unit
        |
        v
MatchFinder dispatches to each Rule::run() callback
        |
        v
Rule::run() emits Findings (optionally with Fix objects) via makeFinding()
        |
        v
Worker returns (findings, exitCode); main thread merges + sorts
(file, line, column, ruleId) ascending, assigns sequential findingIds
        |
        v
IEmitter serializes the AnalysisResult (text / JSON / SARIF) to stdout
(optionally persisted via RunStore::save when --save-run is passed)
```

### Fix flow

```
Source files            or            --run-id=ID
        |                                   |
        v                                   v
runAnalysis() produces               RunStore::load()
findings + fixes                     hydrates a saved AnalysisResult
        \                                   /
         \_________________  _______________/
                           \/
                           v
       Filter by --rule substring and --finding-id
                           |
                           v
   +----------- preview mode ------------+---------- apply mode ----------+
   | FixApplicator::preview() writes     | FixApplicator::apply():        |
   | a per-file text summary, or         |   1. read each target file     |
   | JsonEmitter re-emits the filtered   |   2. optional .bak backup      |
   | findings as JSON.                   |   3. sort fixes by offset desc |
   +-------------------------------------+   4. apply safe replacements   |
                                             5. write modified file      |
                                             returns ApplyResult        |
                                        +---------------------------------+
```

## Extension Points

### Adding a new rule

1. Create `src/rules/<category>/<name>.hpp`. Declare a class inheriting
   from `astharbor::Rule`. The rules are header-only.
2. Implement `id()`, `title()`, `category()`, `summary()`,
   `defaultSeverity()`, `registerMatchers()`, and `run()`.
3. Inside `run()`, use the base-class helpers (`makeFinding()`,
   `emitFinding()`, `nextFixId()`) to avoid boilerplate.
4. Include the header in `src/core/rule_registry.cpp` and add a
   `registry.registerRule(std::make_unique<YourRule>())` call inside
   `registerBuiltinRules()`.

The rule is then automatically visible to every CLI subcommand, every
emitter (text/JSON/SARIF), the fix pipeline, and the MCP frontend.

### Adding a CLI flag

1. Declare a new `llvm::cl::opt<...>` at module scope in
   `src/cli/main.cpp` with `llvm::cl::cat(ASTHarborCategory)`.
2. Read its value inside `runAnalysis()` (for analyze/fix-time flags) or
   the appropriate command handler.
3. If it changes the subprocess invocation shape, also update
   `print_help()` so the CLI help text stays accurate.

### Adding an MCP tool

1. Open `python/astharbor_mcp/server.py` and declare a new function
   decorated with `@mcp.tool()`.
2. Call into `cli_bridge` for synchronous tools, or
   `tasks.manager.start(kind, worker, ...)` for long-running ones.
3. For a new background worker, add the worker function to
   `python/astharbor_mcp/tasks.py` following the
   `analyze_project_worker` signature: it receives the `Task` object as
   its first argument and must return a JSON string (or a value that is
   JSON-serializable).

### Adding a new emitter

1. Implement `IEmitter` (a single `emit()` method) in a new file under
   `src/emitters/`.
2. Wire it into the format selection in `main.cpp`'s `analyze` handler.

## Design Decisions

### Clang LibTooling for the frontend

LibTooling gives the analyzer a full, semantically correct AST with type
information, macro expansion tracking, and source-location mapping. Unlike
regex- or tree-sitter-based approaches, LibTooling can reason about
overload resolution, template instantiation, implicit conversions, and
other constructs that matter for accurate C/C++ analysis.

### Subprocess bridge for MCP

The MCP frontend invokes the CLI binary rather than embedding a C++ library
inside Python:

- **Isolation** — a crash in Clang during analysis cannot bring down the
  MCP server or the agent conversation.
- **Simplicity** — no native Python bindings or FFI to maintain.
- **Reproducibility** — the MCP server produces exactly the same JSON a
  user would get from an equivalent CLI invocation.
- **Deployment flexibility** — the Python package and the C++ binary can
  be versioned, cached, and distributed independently.

### No LLM in the analyzer core

Every finding is the deterministic output of a concrete AST pattern match.
Results are reproducible across runs, there are no API keys or network
calls, false-positive rates are predictable per rule, and the tool can
serve as a ground-truth data source for LLM-powered agents without
introducing circular dependencies.

### Header-only rule classes + shared base helpers

Each rule is a single header under `src/rules/<category>/`. The base
`Rule` class provides `emitFinding`, `makeFinding`, and `nextFixId` so
individual rules do not repeat source-location decomposition, system-header
filtering, or fix-id bookkeeping. This is what makes it practical to
maintain ~46 rules without a library of helpers scattered across the tree.

### Parallel analysis via fresh per-worker registries

`--jobs=N` partitions the source list round-robin and hands each chunk to a
worker that owns its own `RuleRegistry`, `MatchFinder`, and `ClangTool`.
This avoids sharing mutable state between threads and keeps the sequential
path (N=1) as fast as ever. After all workers finish, findings are merged
and sorted by `(file, line, column, ruleId)` so output is deterministic
regardless of which worker finishes first.

## Key Code Locations

For contributors, the landmarks are:

- `include/astharbor/rule.hpp` — the base `Rule` class and its helpers.
- `include/astharbor/rule_registry.hpp`, `src/core/rule_registry.cpp` — the
  central list of shipped rules.
- `include/astharbor/analyzer.hpp`, `src/core/analyzer.cpp` — the
  `Analyzer` driver used by library consumers; `generateRunId()` and
  `assignFindingIds()` live in the header.
- `include/astharbor/run_store.hpp` — JSON persistence layer for saved runs.
- `include/astharbor/fix_applicator.hpp` — preview/apply entry points for
  fixes.
- `src/emitters/{text,json,sarif}_emitter.{cpp,hpp}` — the three shipped
  emitters.
- `src/cli/main.cpp` — CLI dispatch, flag declarations, parallel-analysis
  scheduler, compare-command shell-out.
- `python/astharbor_mcp/server.py` — MCP tool and resource registrations.
- `python/astharbor_mcp/cli_bridge.py` — subprocess wrapper for the native
  binary.
- `python/astharbor_mcp/tasks.py` — background task manager and workers.
- `python/astharbor_mcp/resources.py` — in-memory LRU run cache.

## What's New Since the Original Docs

The analyzer has grown substantially from the initial MVP snapshot the
earlier docs described. Notable changes:

- **46 built-in rules** (up from 27), with new `ub`, `portability`, and
  `best-practice` categories and additional security rules.
- **Three waves of undefined-behavior rules** (`ub/` — 15 rules total)
  covering shifts, arithmetic overflow shapes, polymorphic-deletion
  mistakes, array/`new[]` mismatches, type-punning via casts, and more.
- **Full CLI flag set from the original specification**: `--checks`,
  `--save-run`, `--run-id`, `--finding-id`, `--jobs`, `--changed-only`,
  `--verbose`, `--std`, `--compiler-profile`, `--rule`, `--apply`,
  `--dry-run`, `--backup`, `--format`.
- **Parallel analysis** via `--jobs=N` with deterministic output.
- **Git integration** via `--changed-only` for pre-commit / CI pre-check
  workflows.
- **Run persistence** under `~/.astharbor/runs/` plus
  `fix --run-id`/`--finding-id` replay.
- **Stable sequential `findingId` assignment** so a saved run stays
  addressable.
- **Enriched SARIF output** — `tool.driver.rules` with full metadata,
  `ruleIndex` back-references, and fixes encoded via the standard SARIF
  `fixes`/`artifactChanges`/`replacements` structure.
- **MCP background task system** — `TaskManager` + daemon workers plus
  four new tools (`start_background_analysis`, `get_task_status`,
  `get_task_result`, `list_background_tasks`) so long-running project
  scans do not block the MCP client.
- **MCP run cache** — LRU of 20 `AnalysisResult`s backing the
  `read_finding` tool and the `run://`, `finding://`, `rule://` resources.
- **`compare` command** — minimal `clang++`/`g++` diagnostic counter as a
  first iteration; full cross-compiler diffing is still future work.

Still outstanding: any form of interprocedural or whole-program analysis.
