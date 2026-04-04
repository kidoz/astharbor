# MCP Server

ASTHarbor includes a Python-based MCP (Model Context Protocol) server that
wraps the native CLI binary, making all analysis capabilities available to
LLM agents, IDE extensions, and other MCP clients.

## Overview

The MCP server is implemented with [FastMCP](https://github.com/jlowin/fastmcp)
and lives in the `python/astharbor_mcp/` package. It does not embed Clang or
link against the C++ library directly. Instead, every tool invocation spawns
the `astharbor` CLI binary as a subprocess and returns its output. This
subprocess bridge model keeps the server lightweight and isolated from native
crashes.

## Requirements

- Python >= 3.11
- `fastmcp`
- `pydantic` (v2)

Install the Python package and its dependencies:

```sh
cd python
pip install -e .
```

Or install the dependencies manually:

```sh
pip install fastmcp pydantic
```

The `astharbor` C++ binary must be available either on `PATH` or in one of
the standard build directories (`builddir/`, `build_new/`, `build/`) relative
to the repository root.

## Starting the Server

Using the FastMCP CLI:

```sh
fastmcp run astharbor_mcp.server:mcp
```

Using the package entry point (if installed):

```sh
astharbor-mcp
```

Using Python directly:

```sh
python -m astharbor_mcp.server
```

All methods start the server on **stdio transport** by default, which is the
standard transport for MCP clients that communicate over stdin/stdout.

## Available Tools

### `analyze_file(path: str) -> str`

Analyze a single C/C++ source file. Returns the analysis result as formatted
JSON.

Internally runs:

```sh
astharbor analyze <path> --format=json
```

The raw JSON output is parsed and re-serialized with indentation for
readability. Raises `RuntimeError` if the CLI produces invalid JSON or exits
with code >= 2.

### `analyze_project(directory: str, checks: str = "") -> str`

Analyze all source files in a project directory. The `checks` parameter is
reserved for future rule filtering.

Internally runs:

```sh
astharbor analyze <directory> --format=json --
```

### `list_rules() -> str`

List all available analysis rules in human-readable text format.

Internally runs:

```sh
astharbor rules
```

### `list_rules_json() -> str`

List all available analysis rules in structured JSON format.

Internally runs:

```sh
astharbor rules --format=json
```

### `preview_fix(path: str, rule: str = "") -> str`

Preview available fixes for a file without applying them. Optionally filter
by rule ID pattern.

Internally runs:

```sh
astharbor fix <path> --format=json [--rule=<rule>] --
```

### `apply_fix(path: str, confirm: bool, rule: str = "", backup: bool = True) -> str`

Apply safe fixes to a file. The `confirm` parameter must be set to `True` to
proceed; this acts as a safety gate to prevent accidental modifications.

When `backup` is `True` (the default), `.bak` files are created before any
source file is modified.

Internally runs:

```sh
astharbor fix <path> --apply [--rule=<rule>] [--backup] --format=json --
```

### `doctor_toolchains() -> str`

Run the doctor command to verify that the toolchain environment is healthy,
including rule registration and compilation database availability.

Internally runs:

```sh
astharbor doctor
```

### `read_finding(run_id: str, finding_index: int) -> str`

Read a specific finding from a cached analysis run. The `run_id` is returned
in the JSON output of `analyze_file` or `analyze_project`, and
`finding_index` is the zero-based index into the findings array.

This tool relies on the result caching mechanism (see below).

## Available Resources

MCP resources provide read-only access to cached analysis data using URI
templates.

### `run://{run_id}/summary`

Returns a summary of a cached analysis run, including the run ID, success
status, and the total number of findings.

### `finding://{run_id}/{index}`

Returns the full details of a specific finding (by zero-based index) from a
cached analysis run, including all fix information.

### `rule://{rule_id}`

Returns metadata for a specific rule, including its ID, title, category,
severity, and summary description.

## CLI Bridge Architecture

The bridge between the MCP server and the native CLI follows this pattern:

```
MCP Client (LLM agent, IDE)
        |
        | MCP protocol (stdio)
        v
FastMCP Server (Python)
        |
        | subprocess.run()
        v
astharbor CLI (C++ binary)
        |
        | Clang LibTooling
        v
AST analysis, findings, fixes
        |
        | stdout (text/JSON)
        v
FastMCP Server parses output
        |
        | MCP response
        v
MCP Client
```

### Binary Discovery

The `_get_astharbor_path()` function locates the CLI binary using the
following strategy:

1. Check `PATH` via `shutil.which("astharbor")`.
2. Fall back to known build directories relative to the repository root:
   `builddir/astharbor`, `build_new/astharbor`, `build/astharbor`.
3. Raise `FileNotFoundError` if no executable is found.

### Error Handling

The bridge interprets CLI exit codes as follows:

| Exit Code | Interpretation                                    |
|-----------|---------------------------------------------------|
| 0         | Success, no findings. Return stdout.              |
| 1         | Success, findings present. Return stdout.         |
| >= 2      | Operational failure. Raise `RuntimeError` with stderr or stdout content. |

## Pydantic Models

The `python/astharbor_mcp/models.py` module defines typed data models that
mirror the JSON schema produced by the C++ emitters:

### `Fix`

| Field              | Type   | JSON Alias        | Default    |
|--------------------|--------|--------------------|-----------|
| `fix_id`           | `str`  | `fixId`            | `""`      |
| `description`      | `str`  | --                 | `""`      |
| `safety`           | `str`  | --                 | `"manual"`|
| `replacement_text` | `str`  | `replacementText`  | `""`      |
| `offset`           | `int`  | --                 | `0`       |
| `length`           | `int`  | --                 | `0`       |

### `Finding`

| Field         | Type         | JSON Alias   | Default |
|---------------|--------------|--------------|---------|
| `finding_id`  | `str`        | `findingId`  | `""`    |
| `rule_id`     | `str`        | `ruleId`     | `""`    |
| `severity`    | `str`        | --           | `""`    |
| `category`    | `str`        | --           | `""`    |
| `message`     | `str`        | --           | `""`    |
| `file`        | `str`        | --           | `""`    |
| `line`        | `int`        | --           | `0`     |
| `column`      | `int`        | --           | `0`     |
| `fixes`       | `list[Fix]`  | --           | `[]`    |

### `AnalysisResult`

| Field      | Type             | JSON Alias | Default |
|------------|------------------|------------|---------|
| `run_id`   | `str`            | `runId`    | `""`    |
| `success`  | `bool`           | --         | `True`  |
| `findings` | `list[Finding]`  | --         | `[]`    |

### `ApplyResult`

| Field            | Type        | JSON Alias      | Default |
|------------------|-------------|-----------------|---------|
| `files_modified` | `int`       | `filesModified` | `0`     |
| `fixes_applied`  | `int`       | `fixesApplied`  | `0`     |
| `fixes_skipped`  | `int`       | `fixesSkipped`  | `0`     |
| `errors`         | `list[str]` | --              | `[]`    |

All models use `model_config = {"populate_by_name": True}` to allow
construction with either the Python snake_case field name or the camelCase
JSON alias.

## Result Caching

The MCP server keeps recent analysis results in memory so that follow-up
tools like `read_finding` and resources like `finding://{run_id}/{index}` can
reference specific findings without re-running the analysis. Results are
keyed by `run_id` (a hex-encoded timestamp generated by the CLI, e.g.,
`run-18f3a2b4c10`).

## Transport

The server uses **stdio** transport by default, which is the standard for MCP.
The server reads JSON-RPC messages from stdin and writes responses to stdout.
This makes it compatible with any MCP client that supports the stdio transport,
including Claude Desktop and IDE extensions.

## Example: Claude Desktop Configuration

To add ASTHarbor as an MCP server in Claude Desktop, add the following to your
MCP configuration:

```json
{
  "mcpServers": {
    "astharbor": {
      "command": "fastmcp",
      "args": ["run", "astharbor_mcp.server:mcp"]
    }
  }
}
```

Or if using the installed entry point:

```json
{
  "mcpServers": {
    "astharbor": {
      "command": "astharbor-mcp"
    }
  }
}
```
