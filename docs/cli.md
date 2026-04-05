# CLI Reference

ASTHarbor ships a single binary (`astharbor`) with five subcommands:
`analyze`, `fix`, `rules`, `doctor`, and `compare`. All commands share a
common option parser built on LLVM's `CommandLine` library. The `analyze`
and `fix` commands additionally use Clang's `CommonOptionsParser` for
source-path and compilation-database resolution.

## General Usage

```
astharbor <command> [options] [<path>...] [-- <extra-compiler-flags>]
```

The trailing `--` separator is **required** for `analyze` and `fix` because
`CommonOptionsParser` uses it to delimit source paths from extra compiler
flags. If you have no extra flags to pass, still include the trailing `--`:

```sh
astharbor analyze src/main.cpp --
```

## Exit Codes

| Code | Meaning                                                      |
|------|--------------------------------------------------------------|
| 0    | Success. For `analyze` and `fix`, no findings were produced. |
| 1    | Success, but findings are present.                           |
| 2    | Operational failure: invalid arguments, tool failure, load errors, or an unimplemented branch. |

`doctor` returns 0 when healthy, 1 when unhealthy. `rules` and `compare`
return 0 on success and 2 on argument or invocation errors.

---

## `astharbor analyze`

Run static analysis on the specified source files and emit findings.

```
astharbor analyze [<path>...] [options] [-- <extra-compiler-flags>]
```

If no source paths are supplied, the tool auto-discovers all files from the
compilation database (`compile_commands.json`) resolved by Clang's
`CommonOptionsParser`.

### Options

| Option                       | Description                                                                                                                               | Default  |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|----------|
| `--format=FORMAT`            | Output format: `text`, `json`, or `sarif`                                                                                                 | `text`   |
| `--checks=PATTERNS`          | Comma-separated substring patterns over rule ids. Prefix a pattern with `-` to *disable* matching rules. Empty means "all rules on".     | `""`     |
| `--save-run[=PATH]`          | Persist the result to disk so a later `fix --run-id` can reuse it. With no value, writes `~/.astharbor/runs/<runId>.json`.              | disabled |
| `--jobs=N`                   | Run analysis across N parallel workers. Sources are split round-robin; each worker owns a fresh `RuleRegistry` and `ClangTool`; findings are merged and sorted deterministically. | `1`      |
| `--changed-only`             | Intersect the source list with `git diff --name-only` (uncommitted + staged). Falls back to analyzing everything if git is unavailable. | disabled |
| `--verbose`                  | Print per-file progress, active worker count, and timing to stderr.                                                                     | disabled |
| `--std=VALUE`                | Language standard for single-file mode, e.g. `c++20`, `c17`. Prepended as `-std=<value>` via `ArgumentsAdjuster`.                        | unset    |
| `--compiler-profile=PROFILE` | Compiler dialect profile: `auto` (default), `clang`, or `gcc`. The `gcc` profile inserts `-fgnu-keywords` and `-fgnu89-inline`.          | `auto`   |
| `-p <dir>`                   | Standard Clang tooling flag for specifying the build directory containing `compile_commands.json`.                                       | auto     |
| `-- <flags>`                 | Extra compiler flags forwarded verbatim to Clang.                                                                                         | none     |

### Examples

Basic text output:

```sh
astharbor analyze src/main.cpp --
```

JSON for pipelines:

```sh
astharbor analyze src/ --format=json --
```

SARIF for GitHub Code Scanning:

```sh
astharbor analyze src/ --format=sarif -- > results.sarif
```

Rule filtering: enable only security and modernize rules, and disable
`no-rand`:

```sh
astharbor analyze src/ --checks=security,modernize,-no-rand --
```

Parallel analysis:

```sh
astharbor analyze src/ --jobs=8 --verbose --
```

Changed-only (CI pre-commit style):

```sh
astharbor analyze --changed-only --format=json --
```

Persist a run for later fixing:

```sh
astharbor analyze src/ --save-run --format=json --
```

Single-file mode with an explicit standard (no compile_commands.json):

```sh
astharbor analyze examples/c_sample/foo.c --std=c17 -- -I./include
```

Pass extra compiler flags:

```sh
astharbor analyze src/main.cpp -- -I/usr/local/include -DDEBUG
```

---

## `astharbor fix`

Preview or apply automatic fixes for findings that ship fix information. By
default the command first runs a full analysis, then processes the fixable
findings. With `--run-id` it skips analysis and loads a previously persisted
run instead.

```
astharbor fix [<path>...] [options] [-- <extra-compiler-flags>]
```

Without `--apply`, the command runs in preview mode — nothing is written to
disk. When `--apply` is used, only fixes with `safety: "safe"` are written;
`"review"` and `"manual"` fixes are reported and skipped.

### Options

| Option             | Description                                                                                                                         | Default      |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------|--------------|
| `--dry-run`        | Preview fixes without applying. Same as the default behavior.                                                                        | implicit     |
| `--apply`          | Apply safe fixes to source files.                                                                                                    | disabled     |
| `--rule=PATTERN`   | Only process fixes whose rule id contains the substring PATTERN.                                                                     | all rules    |
| `--run-id=ID`      | Load a previously saved run (`~/.astharbor/runs/<ID>.json`) instead of re-analyzing. Skips source parsing entirely.                  | disabled     |
| `--finding-id=ID`  | Restrict work to a single finding id from the loaded (or freshly produced) run.                                                      | disabled     |
| `--backup`         | Write a `.bak` copy of each file before modifying it.                                                                                | disabled     |
| `--format=FORMAT`  | Output format for summaries: `text` or `json`.                                                                                        | `text`       |
| `--checks`, `--jobs`, `--changed-only`, `--verbose`, `--std`, `--compiler-profile` | Same semantics as `analyze` — used when `fix` re-runs the analyzer to discover findings. | inherited |
| `-- <flags>`       | Extra compiler flags forwarded to Clang.                                                                                              | none         |

### Examples

Preview every available fix on a tree:

```sh
astharbor fix src/ --
```

Preview only one rule:

```sh
astharbor fix src/ --rule=modernize/use-nullptr --
```

Apply safe fixes with backups:

```sh
astharbor fix src/ --apply --backup --
```

Apply fixes and consume the JSON summary:

```sh
astharbor fix src/ --apply --format=json --
```

Reuse a persisted run and fix only one finding:

```sh
astharbor analyze src/ --save-run --format=json --
# … note the runId …
astharbor fix --run-id=run-18f3a2b4c10 --finding-id=finding-0003 --apply --
```

### Output shapes

Apply-mode text output:

```
Applied 5 fix(es) across 3 file(s).
Skipped 2 non-safe fix(es).
```

Apply-mode JSON output:

```json
{
  "filesModified": 3,
  "fixesApplied": 5,
  "fixesSkipped": 2,
  "errors": []
}
```

Preview-mode text output:

```
--- src/main.cpp ---
  4:14 [modernize/use-nullptr] Use nullptr instead of NULL
  Fix (safe): Replace NULL/0 with nullptr
    Replace 4 bytes at offset 38 with "nullptr"

Summary: 1 fix(es) available (1 safe)
```

Preview-mode JSON output mirrors the `analyze --format=json` shape but only
includes findings that carry a `fixes` array.

---

## `astharbor rules`

List every rule registered in the current build.

```
astharbor rules [--format=FORMAT]
```

### Options

| Option             | Description                                          | Default |
|--------------------|------------------------------------------------------|---------|
| `--format=FORMAT`  | Output format: `text` or `json`                      | `text`  |

### Examples

Text:

```sh
astharbor rules
```

```
modernize/use-nullptr - Use nullptr [modernize] (warning)
  Detects NULL and suggests nullptr.
modernize/use-override - Use override [modernize] (warning)
  Detects virtual method overrides missing the override specifier.
bugprone/assignment-in-condition - Assignment in condition [bugprone] (warning)
  Detects assignments used as conditions in if/while statements.
...
```

JSON:

```sh
astharbor rules --format=json
```

```json
[
  {"id": "modernize/use-nullptr", "title": "Use nullptr", "category": "modernize", "severity": "warning", "summary": "Detects NULL and suggests nullptr."},
  {"id": "modernize/use-override", "title": "Use override", "category": "modernize", "severity": "warning", "summary": "Detects virtual method overrides missing the override specifier."}
]
```

---

## `astharbor doctor`

Report on the state of the ASTHarbor toolchain: how many rules are
registered, and whether a compilation database can be discovered from the
current working directory.

```
astharbor doctor [--format=FORMAT]
```

### Options

| Option             | Description                                          | Default |
|--------------------|------------------------------------------------------|---------|
| `--format=FORMAT`  | Output format: `text` or `json`                      | `text`  |

### Examples

```sh
astharbor doctor
```

```
ASTHarbor Doctor
  Rules registered: 46
  Compilation database: found
  Status: OK
```

```sh
astharbor doctor --format=json
```

```json
{
  "rulesRegistered": 46,
  "compilationDatabase": true,
  "healthy": true
}
```

---

## `astharbor compare`

Run `clang++` and `g++` on the same source file with `-fsyntax-only -Wall
-Wextra` and report a minimal diagnostic counter for each compiler. This is a
sanity check that your code parses under both frontends — it is **not** a
full cross-compiler diff.

```
astharbor compare <file> [--format=FORMAT]
```

### Options

| Option             | Description                                          | Default |
|--------------------|------------------------------------------------------|---------|
| `--format=FORMAT`  | Output format: `text` or `json`                      | `text`  |

The language (`-xc` vs `-xc++`) is chosen from the file extension
(`.cpp`, `.cc`, `.cxx`, `.hpp` → C++; everything else → C). If either
compiler is missing from `PATH`, that half of the report is marked
unavailable.

### Examples

```sh
astharbor compare src/main.cpp
```

```
ASTHarbor Compare: src/main.cpp
  clang++: exit=0, diagnostics=2
  g++:     exit=0, diagnostics=1
  Agreement: NO — compilers differ
```

```sh
astharbor compare src/main.cpp --format=json
```

```json
{
  "file": "src/main.cpp",
  "clang": {"available": true, "exit": 0, "diagnostics": 2},
  "gcc": {"available": true, "exit": 0, "diagnostics": 1},
  "agreement": false
}
```

---

## Compilation Database

ASTHarbor relies on a `compile_commands.json` file to learn the exact
compiler flags, include paths, and macro definitions for each translation
unit. Typical build systems produce it as follows:

- **Meson**: written automatically into the build directory.
- **CMake**: pass `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.
- **Bear**: wrap your make command with `bear -- make`.

Clang's `CommonOptionsParser` searches for `compile_commands.json` starting
at the current directory and walking up to parents. You can also specify the
build directory explicitly via `-p`:

```sh
astharbor analyze src/main.cpp -- -p /path/to/builddir
```

For single-file runs where no compilation database exists, use `--std` (and
optionally `--compiler-profile` and extra `-I/-D` flags after `--`) to
provide the minimum context the frontend needs.

## Notes

- `analyze` and `fix` require the trailing `--` because of
  `CommonOptionsParser`'s argument grammar. Omitting it may cause confusing
  argument-parsing errors.
- When no source files are specified and the compilation database is empty
  or missing, `analyze` exits with code 2.
- SARIF output is produced only by `analyze`. `fix`, `rules`, `doctor`, and
  `compare` support `text` and `json` only.
- `--jobs=N` is ignored in single-file invocations (worker count is clamped
  to the number of source files).
- `--save-run` persists to `~/.astharbor/runs/` by default. The directory is
  created on demand; if `$HOME` is unset, the tool falls back to the system
  temp directory.
