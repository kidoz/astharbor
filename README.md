# ASTHarbor

ASTHarbor is a Clang-first static analyzer for C and C++. It is deterministic
by construction (no LLM in the analysis core), respects real project build
settings via `compile_commands.json`, and suggests fixes with explicit safety
labels. It ships a native CLI for humans and CI, and a FastMCP server so AI
agents can drive the same pipeline over stdio.

## Architecture Overview

- **Core Analyzer (C++23)**: A static library (`libastharbor`) built with
  Meson on top of Clang LibTooling and AST Matchers. It owns the rule
  registry, analyzer driver, emitters (text / JSON / SARIF), fix applicator,
  and run-store persistence layer.
- **CLI Frontend (C++)**: The `astharbor` binary parses arguments via LLVM's
  `CommandLine` library and Clang's `CommonOptionsParser`, and dispatches to
  the `analyze`, `fix`, `rules`, `doctor`, and `compare` subcommands.
- **MCP Frontend (Python)**: `astharbor_mcp` is a FastMCP server that exposes
  analysis tools, resources, and a background task system to MCP clients. It
  invokes the native CLI as a subprocess so native crashes cannot take the
  server down.

The project currently registers **~46 rules** across eight categories:
`bugprone`, `modernize`, `performance`, `readability`, `security`, `ub`,
`portability`, and `best-practice`.

## Build Instructions

ASTHarbor requires LLVM/Clang (version 14 or higher) and Meson.

```bash
# Configure a build directory with clang as the host compiler
CXX=clang++ CC=clang meson setup build

# Compile the project (produces `build/astharbor` and `build/libastharbor.a`)
meson compile -C build

# Run the C++ unit tests
meson test -C build
```

To set up the Python MCP server:

```bash
cd python
python3 -m venv venv
source venv/bin/activate
pip install -e . pytest
```

## CLI Usage Examples

All `analyze` and `fix` invocations end in a trailing `--` so Clang's
`CommonOptionsParser` can separate source paths from extra compiler flags.

```bash
# Analyze a single file with text output
astharbor analyze examples/cpp_sample/main.cpp --

# Emit JSON for tooling pipelines
astharbor analyze src/main.cpp --format=json --

# Emit SARIF for GitHub Code Scanning and other SARIF consumers
astharbor analyze src/ --format=sarif -- > results.sarif

# Run only a subset of rules (comma-separated substrings; prefix '-' to exclude)
astharbor analyze src/ --checks=security,-no-rand --

# Persist the run so a later `fix` invocation can reuse it
astharbor analyze src/ --save-run --format=json --

# Parallel analysis across four workers
astharbor analyze src/ --jobs=4 --

# Restrict to files git reports as modified (staged + unstaged)
astharbor analyze src/ --changed-only --

# Verbose progress + timing to stderr
astharbor analyze src/ --verbose --

# Force a language standard in single-file mode (no compile_commands.json)
astharbor analyze examples/c_sample/foo.c --std=c17 --

# Pick a compiler dialect profile (auto, clang, or gcc)
astharbor analyze src/legacy.cpp --compiler-profile=gcc --

# Preview available fixes (default mode, read-only)
astharbor fix src/ --

# Apply only safe fixes, backing up originals to <file>.bak
astharbor fix src/ --apply --backup --

# Explicit dry-run against a specific rule
astharbor fix src/ --dry-run --rule=modernize/use-nullptr --

# Replay a persisted run and target a single finding by id
astharbor fix --run-id=run-18f3a2b4c10 --finding-id=finding-0003 --apply --

# List all registered rules (text or JSON)
astharbor rules
astharbor rules --format=json

# Check toolchain health (text or JSON)
astharbor doctor
astharbor doctor --format=json

# Compare the clang and gcc frontends on a single source file
astharbor compare src/main.cpp
```

See [docs/cli.md](docs/cli.md) for a full flag-by-flag reference.

### Notable CLI flags

| Flag                     | Commands       | Purpose                                                               |
|--------------------------|---------------|-----------------------------------------------------------------------|
| `--format`               | all           | `text`, `json`, or `sarif` (where applicable)                        |
| `--checks`               | analyze, fix  | Comma-separated substring include/exclude patterns for rule ids      |
| `--save-run[=PATH]`      | analyze       | Persist the run to `~/.astharbor/runs/<runId>.json` or a custom path |
| `--run-id`               | fix           | Reuse a previously persisted run instead of re-analyzing             |
| `--finding-id`           | fix           | Restrict work to a single finding id from the loaded run            |
| `--jobs=N`               | analyze, fix  | Parallel analysis workers (round-robin source partitioning)         |
| `--changed-only`         | analyze, fix  | Intersect the source list with `git diff --name-only`               |
| `--verbose`              | analyze, fix  | Per-file progress, rule count, and timing on stderr                 |
| `--std`                  | analyze, fix  | Language standard for single-file invocations (`c++20`, `c17`, ...) |
| `--compiler-profile`     | analyze, fix  | Compiler dialect: `auto` (default), `clang`, or `gcc`               |
| `--rule=PATTERN`         | fix           | Only act on findings whose rule id matches the substring            |
| `--apply`                | fix           | Actually modify source files (safe fixes only)                      |
| `--dry-run`              | fix           | Preview mode (default if neither `--apply` nor `--dry-run` passed)  |
| `--backup`               | fix           | Write a `.bak` copy before applying fixes                           |

## MCP Server Usage

The Python MCP server wraps the CLI and exposes it over the standard stdio
transport. Start it with any of:

```bash
# Via the FastMCP CLI
fastmcp run astharbor_mcp.server:mcp

# Via the installed entry point
astharbor-mcp

# Directly with Python
python -m astharbor_mcp.server
```

### Available tools

| Tool                         | Purpose                                                              |
|------------------------------|----------------------------------------------------------------------|
| `analyze_file(path)`         | Analyze a single file, return JSON result                           |
| `analyze_project(dir, checks)` | Analyze a directory using its compilation database                 |
| `list_rules()`               | List rules in human-readable text                                    |
| `list_rules_json()`          | List rules as structured JSON                                        |
| `preview_fix(path, rule)`    | Preview available fixes without writing to disk                     |
| `apply_fix(path, confirm, rule, backup)` | Apply safe fixes after explicit confirmation           |
| `doctor_toolchains()`        | Toolchain and rule-registration health check                        |
| `read_finding(run_id, index)` | Read a single finding from a cached run                            |
| `start_background_analysis(dir, checks, jobs)` | Launch `analyze_project` in a daemon thread and return a task id immediately |
| `get_task_status(task_id)`   | Poll a background task: status, progress, elapsed seconds, error   |
| `get_task_result(task_id)`   | Fetch the final JSON of a completed background task                 |
| `list_background_tasks()`    | Enumerate all background tasks seen in the current session          |

### Available resources

- `run://{run_id}/summary` — per-run totals, severity/category breakdowns.
- `finding://{run_id}/{index}` — full details of a finding from a cached run.
- `rule://{rule_id}` — rule metadata (id, title, category, severity, summary).

See [docs/mcp.md](docs/mcp.md) for the complete tool and resource reference,
and [docs/architecture.md](docs/architecture.md) for a deeper walkthrough of
the runtime.

## Example JSON Output

```json
{
  "runId": "run-18f3a2b4c10",
  "success": true,
  "findings": [
    {
      "findingId": "finding-0000",
      "ruleId": "modernize/use-nullptr",
      "severity": "warning",
      "message": "Use nullptr instead of NULL",
      "category": "modernize",
      "file": "/path/to/main.cpp",
      "line": 2,
      "column": 14,
      "fixes": [
        {
          "fixId": "use-nullptr-0",
          "description": "Replace NULL/0 with nullptr",
          "safety": "safe",
          "replacementText": "nullptr",
          "offset": 38,
          "length": 4
        }
      ]
    }
  ]
}
```

## Example Fix Preview

```
--- src/main.cpp ---
  4:14 [modernize/use-nullptr] Use nullptr instead of NULL
  Fix (safe): Replace NULL/0 with nullptr
    Replace 4 bytes at offset 38 with "nullptr"

Summary: 1 fix(es) available (1 safe)
```

## How to add a new rule

1. Create a new header in `src/rules/<category>/<name>.hpp` inheriting from
   `astharbor::Rule`.
2. Override `id()`, `title()`, `category()`, `summary()`, and
   `defaultSeverity()`.
3. Implement `registerMatchers(clang::ast_matchers::MatchFinder &Finder)` to
   bind your AST matchers.
4. Implement `run(const clang::ast_matchers::MatchFinder::MatchResult &Result)`
   and use the base class helpers `makeFinding()`, `emitFinding()`, and
   `nextFixId()` to populate the `findings` vector.
5. Register your rule in `src/core/rule_registry.cpp` inside
   `registerBuiltinRules()`.

No other wiring is required — the new rule is automatically visible to every
CLI subcommand, every output format, the fix pipeline, and the MCP server.
See [docs/rules.md](docs/rules.md) for per-rule authoring conventions.
