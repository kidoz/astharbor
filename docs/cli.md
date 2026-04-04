# CLI Reference

ASTHarbor provides a single binary (`astharbor`) with several subcommands for
analyzing C/C++ source code, applying fixes, listing rules, and checking
toolchain health.

## General Usage

```
astharbor <command> [options] [<path>...] [-- <extra-compiler-flags>]
```

The trailing `--` separator is **required** for the `analyze` and `fix`
commands. These commands use Clang's `CommonOptionsParser` internally, which
expects `--` to delimit source paths from compiler flags. If you have no extra
compiler flags to pass, still include the trailing `--`:

```sh
astharbor analyze src/main.cpp --
```

## Commands

---

### `astharbor analyze`

Run static analysis on the specified source files and emit findings.

```
astharbor analyze [<path>...] [--format=FORMAT] [-- <extra-compiler-flags>]
```

If no source paths are given, the tool auto-discovers all files from the
compilation database (`compile_commands.json`).

#### Options

| Option              | Description                                          | Default |
|---------------------|------------------------------------------------------|---------|
| `--format=FORMAT`   | Output format: `text`, `json`, or `sarif`            | `text`  |
| `--compdb PATH`     | Path to directory containing `compile_commands.json` (resolved by Clang's `CommonOptionsParser`) | auto-detected |
| `-- <flags>`        | Extra compiler flags passed to Clang (e.g., `-std=c++20 -I/opt/include`) | none |

#### Examples

Analyze a single file with text output:

```sh
astharbor analyze src/main.cpp --
```

Analyze a directory with JSON output:

```sh
astharbor analyze src/ --format=json --
```

Analyze with SARIF output for CI integration:

```sh
astharbor analyze src/ --format=sarif -- > results.sarif
```

Analyze with extra include paths:

```sh
astharbor analyze src/main.cpp -- -I/usr/local/include -DDEBUG
```

Analyze all files in the compilation database (no paths needed):

```sh
astharbor analyze --format=json --
```

---

### `astharbor fix`

Preview or apply automatic fixes for findings that have associated fix
information. The command first runs a full analysis, then processes the fixable
findings.

```
astharbor fix [<path>...] [--apply] [--dry-run] [--rule=PATTERN] [--backup] [--format=FORMAT] [-- <extra-compiler-flags>]
```

By default (without `--apply`), the command operates in preview mode, showing
what fixes are available without modifying any files.

#### Options

| Option              | Description                                          | Default       |
|---------------------|------------------------------------------------------|---------------|
| `--dry-run`         | Preview fixes without applying (same as default)     | enabled       |
| `--apply`           | Apply safe fixes to source files                     | disabled      |
| `--rule=PATTERN`    | Only process fixes for rule IDs matching PATTERN (substring match) | all rules |
| `--backup`          | Create `.bak` backup files before modifying sources  | disabled      |
| `--format=FORMAT`   | Output format: `text` or `json`                      | `text`        |
| `-- <flags>`        | Extra compiler flags passed to Clang                 | none          |

When `--apply` is given, only fixes with `safety: "safe"` are applied. Fixes
marked `"review"` or `"manual"` are skipped and reported in the summary.

#### Examples

Preview all available fixes:

```sh
astharbor fix src/ --
```

Preview fixes for a specific rule:

```sh
astharbor fix src/ --rule=modernize/use-nullptr --
```

Apply safe fixes with backup:

```sh
astharbor fix src/ --apply --backup --
```

Apply fixes and get JSON output:

```sh
astharbor fix src/ --apply --format=json --
```

Text output in apply mode:

```
Applied 5 fix(es) across 3 file(s).
Skipped 2 non-safe fix(es).
```

JSON output in apply mode:

```json
{
  "filesModified": 3,
  "fixesApplied": 5,
  "fixesSkipped": 2,
  "errors": []
}
```

Preview mode text output:

```
--- src/main.cpp ---
  4:14 [modernize/use-nullptr] Use nullptr instead of NULL
  Fix (safe): Replace NULL/0 with nullptr
    Replace 4 bytes at offset 38 with "nullptr"

Summary: 1 fix(es) available (1 safe)
```

---

### `astharbor rules`

List all registered analysis rules.

```
astharbor rules [--format=FORMAT]
```

#### Options

| Option              | Description                                          | Default |
|---------------------|------------------------------------------------------|---------|
| `--format=FORMAT`   | Output format: `text` or `json`                      | `text`  |

#### Examples

List rules in text format:

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

List rules in JSON format:

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

### `astharbor doctor`

Check the toolchain environment: whether rules are registered and whether a
compilation database is available in the current directory.

```
astharbor doctor [--format=FORMAT]
```

#### Options

| Option              | Description                                          | Default |
|---------------------|------------------------------------------------------|---------|
| `--format=FORMAT`   | Output format: `text` or `json`                      | `text`  |

#### Examples

```sh
astharbor doctor
```

```
ASTHarbor Doctor
  Rules registered: 27
  Compilation database: found
  Status: OK
```

```sh
astharbor doctor --format=json
```

```json
{
  "rulesRegistered": 27,
  "compilationDatabase": true,
  "healthy": true
}
```

---

### `astharbor compare`

Compare analysis results between two runs or branches. This command is
**not yet implemented** and will exit with code 2.

```sh
astharbor compare
# Error: 'compare' command is not yet implemented.
```

---

## Exit Codes

| Code | Meaning                                                      |
|------|--------------------------------------------------------------|
| 0    | Success. For `analyze` and `fix`, no findings were produced. |
| 1    | Success, but findings are present. For `doctor`, the environment is unhealthy. |
| 2+   | Operational failure: invalid arguments, compilation errors, file I/O errors, or unimplemented command. |

## Compilation Database

ASTHarbor relies on a `compile_commands.json` file to understand compiler
flags, include paths, and defines for each translation unit. This file is
typically generated by your build system:

- **Meson**: generated automatically in the build directory.
- **CMake**: pass `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.
- **Bear**: wrap your make command with `bear -- make`.

The `CommonOptionsParser` searches for `compile_commands.json` starting from
the current directory and walking up to parent directories. You can also
specify the path explicitly via the `-p` flag (a Clang tooling flag, passed
after `--`):

```sh
astharbor analyze src/main.cpp -- -p /path/to/builddir
```

## Notes

- The `analyze` and `fix` commands require a trailing `--` due to Clang
  tooling's argument parsing conventions. Omitting it may cause unexpected
  argument parsing behavior.
- When no source files are specified, the tool attempts to discover them from
  the compilation database. If the database is empty or missing, the tool
  exits with code 2.
- SARIF output is available only for the `analyze` command. The `fix` command
  supports `text` and `json` formats.
