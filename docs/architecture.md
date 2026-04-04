# Architecture

## High-Level Overview

ASTHarbor is a C/C++ static analysis tool built on Clang LibTooling. It has two
frontends (a native CLI and a Python MCP server) that share a single core
analysis library.

```
                          +---------------------+
                          |    User / IDE / AI   |
                          +----------+----------+
                                     |
                  +------------------+------------------+
                  |                                     |
         +--------v--------+                  +---------v--------+
         |   CLI Frontend  |                  |  MCP Frontend    |
         |   (C++ binary)  |                  |  (Python/FastMCP)|
         +--------+--------+                  +---------+--------+
                  |                                     |
                  |                           subprocess invocation
                  |                                     |
                  +------------------+------------------+
                                     |
                          +----------v----------+
                          | Core Analyzer Library|
                          |   (libastharbor.a)  |
                          +----------+----------+
                                     |
              +----------------------+----------------------+
              |              |               |              |
     +--------v---+  +------v------+  +-----v-----+  +----v------+
     | Rule       |  | Compilation |  | Emitters   |  | Fix       |
     | Registry   |  | Database    |  | (text/json |  | Applicator|
     |            |  | Handling    |  |  /sarif)   |  |           |
     +------------+  +-------------+  +-----------+  +-----------+
              |
     +--------v--------+
     | AST Matcher Rules|
     | (27 built-in)   |
     +-----------------+
```

## Core Analyzer Library (C++23)

The core is compiled as a static library (`libastharbor.a`) using Meson and
linked against `libclang-cpp`. It requires LLVM >= 14.0 and uses the C++23
standard.

### Compilation Database Handling

The `CompilationDB` class (`include/astharbor/compilation_db.hpp`) wraps Clang's
`CompilationDatabase`. When analyzing files, the CLI uses Clang's
`CommonOptionsParser` to automatically locate a `compile_commands.json` file
in the current or parent directories. If no source files are explicitly listed,
the tool auto-discovers all files from the compilation database.

### Rule Registry

The `RuleRegistry` (`include/astharbor/rule_registry.hpp`) holds a vector of
`std::unique_ptr<Rule>` instances. The free function `registerBuiltinRules()`
(`src/core/rule_registry.cpp`) populates the registry with all 27 built-in
rules, organized into five categories:

| Category      | Example Rules                                              |
|---------------|------------------------------------------------------------|
| `bugprone`    | assignment-in-condition, identical-expressions, suspicious-memset, suspicious-semicolon, unsafe-memory-operation |
| `modernize`   | use-nullptr, use-override                                 |
| `performance` | for-loop-copy                                              |
| `readability` | const-return-type, container-size-empty                    |
| `security`    | no-gets, no-sprintf, no-strcpy-strcat, unsafe-printf-format, unsafe-temp-file, unchecked-realloc, no-system-call, no-atoi, deprecated-crypto-call, no-alloca, no-signal, no-rand, missing-return-value-check, no-scanf-without-width, signed-arith-in-alloc, large-stack-array, integer-signedness-mismatch |

### Rule Base Class

Every rule inherits from `Rule` (`include/astharbor/rule.hpp`), which itself
extends `clang::ast_matchers::MatchFinder::MatchCallback`. A rule must
implement:

- `id()` -- unique identifier, e.g., `"modernize/use-nullptr"`
- `title()` -- human-readable short name
- `category()` -- grouping category
- `summary()` -- one-line description
- `defaultSeverity()` -- `"warning"`, `"error"`, etc.
- `registerMatchers(MatchFinder &)` -- bind AST matchers
- `run(MatchResult &)` -- handle each match, push to `findings` vector

The base class also provides `isInSystemHeader()` so rules can skip findings
inside system headers.

### Finding and Fix Models

A `Finding` (`include/astharbor/finding.hpp`) captures one diagnostic:

```cpp
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
```

A `Fix` (`include/astharbor/fix.hpp`) describes a concrete source edit:

```cpp
struct Fix {
    std::string fixId;
    std::string description;
    std::string safety;         // "safe", "review", or "manual"
    std::string replacementText;
    int offset = 0;
    int length = 0;
};
```

An `AnalysisResult` (`include/astharbor/result.hpp`) bundles a run ID, success
flag, and the collected findings.

### Emitters

Emitters implement the `IEmitter` interface (`include/astharbor/emitter.hpp`):

```cpp
class IEmitter {
  public:
    virtual void emit(const AnalysisResult &result, std::ostream &out) = 0;
};
```

Three emitters are provided:

- **TextEmitter** (`src/emitters/text_emitter.cpp`) -- Clang-style
  `file:line:col: warning: message [rule-id]` output.
- **JsonEmitter** (`src/emitters/json_emitter.cpp`) -- Structured JSON with
  runId, success flag, and findings array (including fixes).
- **SarifEmitter** (`src/emitters/sarif_emitter.cpp`) -- SARIF v2.1.0 format
  for integration with GitHub Code Scanning and other SARIF consumers.

### Fix Applicator

The `FixApplicator` (`include/astharbor/fix_applicator.hpp`) is a static
utility class with two modes:

- `preview()` -- prints a human-readable summary of available fixes grouped
  by file, without modifying anything.
- `apply()` -- reads each file, optionally creates a `.bak` backup, applies
  fixes from end-of-file to beginning (to preserve offsets), and writes the
  result. Only `"safe"` fixes are applied by default.

## CLI Frontend

The CLI (`src/cli/main.cpp`) is a standalone executable that links against
`libastharbor`. It uses LLVM's `cl::opt` CommandLine library for option
parsing and Clang's `CommonOptionsParser` for source file and compilation
database resolution.

Subcommands:

| Command   | Description                          |
|-----------|--------------------------------------|
| `analyze` | Run analysis, emit findings          |
| `fix`     | Preview or apply automatic fixes     |
| `rules`   | List all registered rules            |
| `doctor`  | Check toolchain and environment      |
| `compare` | Reserved, not yet implemented        |

See [cli.md](cli.md) for the full command reference.

## MCP Frontend (Python)

The MCP frontend (`python/astharbor_mcp/`) is a Python package that exposes
the ASTHarbor CLI as a set of MCP (Model Context Protocol) tools using the
FastMCP framework.

### CLI Bridge Subprocess Model

The MCP server does not link against `libastharbor` or use Clang bindings
directly. Instead, each tool invocation spawns the `astharbor` CLI binary as
a subprocess via `subprocess.run()`. The bridge function
(`python/astharbor_mcp/server.py::_run_astharbor`) handles:

1. Locating the `astharbor` binary (PATH lookup, then build directory fallback).
2. Invoking it with the appropriate subcommand and flags.
3. Interpreting exit codes (>= 2 is an operational failure; 0-1 are normal).
4. Returning stdout as the tool result.

### Pydantic Models

The `models.py` module defines Pydantic v2 models that mirror the C++ data
structures: `Fix`, `Finding`, `AnalysisResult`, and `ApplyResult`. These use
`Field(alias=...)` to map between the camelCase JSON produced by the CLI and
snake_case Python attributes.

### Resource Endpoints

The MCP server can expose resources for cached analysis runs, allowing clients
to reference findings by run ID and index after an analysis completes.

See [mcp.md](mcp.md) for the full MCP reference.

## Data Flow

### Analysis Flow

```
Source files (*.cpp, *.c)
        |
        v
CommonOptionsParser (resolves compile_commands.json)
        |
        v
ClangTool (Clang LibTooling frontend)
        |
        v
AST parsing (per translation unit)
        |
        v
MatchFinder dispatches to registered Rule callbacks
        |
        v
Each Rule::run() inspects the match, creates Finding objects
(optionally with Fix objects attached)
        |
        v
Analyzer collects all findings into an AnalysisResult
        |
        v
IEmitter formats the result (text / JSON / SARIF) to stdout
```

### Fix Flow

```
Source files
        |
        v
Full analysis (same as above) produces findings with fixes
        |
        v
Filter by --rule pattern (if provided)
        |
        v
FixApplicator::preview()      or      FixApplicator::apply()
  (print summary)                       |
                                        v
                                  Read file content
                                        |
                                        v
                                  Create .bak backup (if --backup)
                                        |
                                        v
                                  Sort fixes by offset descending
                                        |
                                        v
                                  Apply replacements end-to-start
                                        |
                                        v
                                  Write modified file
```

## Extension Points

### Adding a New Rule

1. Create a header file in the appropriate `src/rules/<category>/` directory.
2. Define a class that inherits from `astharbor::Rule`.
3. Implement all pure virtual methods (`id`, `title`, `category`, `summary`,
   `defaultSeverity`, `registerMatchers`, `run`).
4. In `run()`, push `Finding` objects (optionally with `Fix` objects) to the
   inherited `findings` vector.
5. Include the header in `src/core/rule_registry.cpp` and add a
   `registerRule(std::make_unique<YourRule>())` call in `registerBuiltinRules()`.

No other changes are needed. The rule is automatically available in all
frontends, all output formats, and the fix workflow.

### Adding a New Emitter

1. Create a class that implements `IEmitter` (a single `emit()` method).
2. Wire it into the CLI's format selection logic in `src/cli/main.cpp`.

## Design Decisions

### Why Clang LibTooling?

Clang LibTooling provides a full, semantically correct AST with type
information, macro expansion tracking, and source location mapping. Unlike
regex-based or tree-sitter-based approaches, LibTooling can reason about
overload resolution, template instantiation, implicit conversions, and other
language features that matter for accurate static analysis of C and C++ code.

### Why a Subprocess Bridge for MCP?

The MCP frontend invokes the CLI binary rather than embedding a C++ library:

- **Isolation**: a crash in Clang analysis does not bring down the MCP server.
- **Simplicity**: no native Python bindings or FFI layer to maintain.
- **Deployment flexibility**: the Python package and the C++ binary can be
  built, versioned, and distributed independently.
- **Reproducibility**: the MCP server produces exactly the same results as
  a direct CLI invocation.

### Why No LLM in the Core?

ASTHarbor is a deterministic, rule-based analyzer. Every finding is the direct
result of a concrete AST pattern match. This means:

- Results are reproducible across runs.
- No API keys, network calls, or token budgets are required.
- False positive rates are predictable and controllable per rule.
- The tool can serve as a reliable ground-truth data source for LLM-powered
  agents (via MCP) without introducing circular dependencies.
