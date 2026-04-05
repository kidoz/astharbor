# MCP Server

ASTHarbor ships a Python MCP (Model Context Protocol) server that wraps the
native CLI and exposes it to LLM agents, IDE extensions, and other MCP
clients. The server lives in `python/astharbor_mcp/` and uses
[FastMCP](https://github.com/jlowin/fastmcp).

The server never links against Clang or `libastharbor` directly. Every tool
invocation shells out to the `astharbor` binary via `subprocess.run()` and
parses the resulting stdout. This subprocess bridge keeps the server small,
isolates it from native crashes, and makes the MCP frontend version-agnostic
with respect to the underlying C++ build.

## Requirements

- Python >= 3.11
- `fastmcp`
- `pydantic` (v2)
- `mcp`

Install from the repository:

```sh
cd python
pip install -e .
```

Or install the dependencies by hand:

```sh
pip install fastmcp pydantic mcp
```

The `astharbor` native binary must be available either on `PATH` or in one
of the known build directories relative to the repository root
(`buildDir/`, `builddir/`, `build_new/`, `build/`). The bridge searches in
that order.

## Starting the Server

Via the FastMCP CLI:

```sh
fastmcp run astharbor_mcp.server:mcp
```

Via the installed entry point:

```sh
astharbor-mcp
```

Directly with Python:

```sh
python -m astharbor_mcp.server
```

All three start the server on the standard MCP **stdio** transport: JSON-RPC
messages come in on stdin, responses go out on stdout.

## Tools

The server exposes **ten tools**, grouped into foreground analysis, fix
operations, and the background task system.

### Foreground tools

#### `analyze_file(path: str) -> str`

Analyze a single C/C++ source file. Internally runs:

```sh
astharbor analyze <path> --format=json --
```

The JSON is parsed into the `AnalysisResult` Pydantic model, stored in the
LRU run cache, and re-serialized with indentation. Raises `RuntimeError` on
invalid JSON or if the CLI exits with code >= 2.

#### `analyze_project(directory: str, checks: str = "") -> str`

Analyze all source files resolved from a project directory. When `checks` is
non-empty, it is forwarded verbatim as `--checks=<value>`.

```sh
astharbor analyze <directory> --format=json [--checks=<checks>] --
```

Result is cached and returned as indented JSON.

#### `list_rules() -> str`

List every registered rule in human-readable text form.

```sh
astharbor rules
```

#### `list_rules_json() -> str`

Same as `list_rules`, but returns structured JSON.

```sh
astharbor rules --format=json
```

#### `preview_fix(path: str, rule: str = "") -> str`

Preview available fixes for a file without applying them. Optional rule
filter is passed through as a substring match.

```sh
astharbor fix <path> --dry-run --format=json [--rule=<rule>] --
```

#### `apply_fix(path: str, confirm: bool, rule: str = "", backup: bool = True) -> str`

Apply safe fixes to a file. The `confirm` parameter must be `True`; this is
a safety gate to prevent accidental writes. When `backup` is `True` (the
default), `.bak` files are produced before sources are modified.

```sh
astharbor fix <path> --apply --format=json [--rule=<rule>] [--backup] --
```

#### `doctor_toolchains() -> str`

Run the doctor command and return its text output.

```sh
astharbor doctor
```

#### `read_finding(run_id: str, finding_index: int) -> str`

Read a specific finding from a cached analysis run. The `run_id` is the one
returned inside the JSON produced by `analyze_file` or `analyze_project`;
`finding_index` is a zero-based index into the `findings` array. Returns an
error string if the run or index is unknown.

### Background task tools

Long-running analyses (whole-project scans, `--jobs=N` runs) can easily
exceed the response window of an MCP client. The background-task API lets a
client kick off work, return to its user, and poll for completion.

All background state lives in an in-process `TaskManager` defined in
`python/astharbor_mcp/tasks.py`. Tasks run in daemon threads, so they die
with the server process.

#### `start_background_analysis(directory: str, checks: str = "", jobs: int = 1) -> str`

Kick off an `analyze_project` run in a daemon worker thread and return
immediately. The response is:

```json
{
  "taskId": "task-a1b2c3d4e5f6",
  "status": "started"
}
```

Internally the worker runs:

```sh
astharbor analyze <directory> --format=json [--checks=<checks>] [--jobs=<jobs>] --
```

Its JSON result is parsed, cached in the run cache, and held on the task
object until `get_task_result` is called.

#### `get_task_status(task_id: str) -> str`

Poll the current state of a background task. Returns JSON:

```json
{
  "taskId": "task-a1b2c3d4e5f6",
  "kind": "analyze_project",
  "status": "running",
  "progress": "invoking astharbor analyze on src/",
  "elapsedSeconds": 3.142,
  "hasResult": false,
  "error": null
}
```

`status` cycles through `pending`, `running`, then either `completed` or
`failed`.

#### `get_task_result(task_id: str) -> str`

Return the final JSON payload of a completed task. If the task is still
running, returns a human-readable message advising the caller to keep
polling. If the task failed, returns an error string containing the captured
exception.

#### `list_background_tasks() -> str`

Enumerate every task the `TaskManager` has seen in the current server
session:

```json
[
  {"taskId": "task-a1b2c3d4e5f6", "kind": "analyze_project", "status": "completed"},
  {"taskId": "task-f0e9d8c7b6a5", "kind": "analyze_project", "status": "running"}
]
```

## Resources

MCP resources provide read-only access to cached analysis data via URI
templates. They pair well with the background tools: start an analysis,
remember the `run_id` it returns, then use resources to drill into
individual findings as the conversation progresses.

### `run://{run_id}/summary`

Returns a summary for a cached run:

```json
{
  "runId": "run-18f3a2b4c10",
  "success": true,
  "totalFindings": 17,
  "bySeverity": {"warning": 14, "error": 3},
  "byCategory": {"security": 9, "ub": 5, "bugprone": 3}
}
```

### `finding://{run_id}/{index}`

Returns the full details of a specific finding (by zero-based index) from a
cached analysis run, including all fix objects.

### `rule://{rule_id}`

Returns metadata for a specific rule: id, title, category, severity, and
summary. Looks the rule up by re-running `astharbor rules --format=json`.

## Architecture

```
MCP Client (LLM agent, IDE)
        |
        | MCP JSON-RPC over stdio
        v
FastMCP Server (Python)
   |           |
   | cli_bridge| tasks.manager (daemon threads)
   v           v
astharbor CLI (native, subprocess.run)
        |
        | Clang LibTooling + AST matchers
        v
Findings, fixes, run ids
        |
        | stdout (text / JSON)
        v
FastMCP parses into Pydantic models, caches in RunCache
        |
        | MCP response
        v
MCP Client
```

### Binary discovery

`cli_bridge.get_astharbor_path()`:

1. Checks `PATH` via `shutil.which("astharbor")`.
2. Falls back to build directories relative to the repo root, tried in order
   `buildDir`, `builddir`, `build_new`, `build`.
3. Raises `FileNotFoundError` if nothing is found.

### Exit-code handling

| Exit Code | Interpretation                                              |
|-----------|-------------------------------------------------------------|
| 0         | Success, no findings. `run_cli` returns stdout.             |
| 1         | Success, findings present. `run_cli` returns stdout.        |
| >= 2      | Operational failure. `run_cli` raises `RuntimeError` with the first non-empty of stderr/stdout. |

### Pydantic models

`python/astharbor_mcp/models.py` defines typed models that mirror the JSON
schema produced by the C++ emitters. Every field carries an alias for the
camelCase form the CLI emits, and the models are configured with
`model_config = {"populate_by_name": True}` so they can be constructed from
either naming convention.

#### `Fix`

| Field              | Type   | JSON Alias        | Default    |
|--------------------|--------|--------------------|-----------|
| `fix_id`           | `str`  | `fixId`            | `""`      |
| `description`      | `str`  | --                 | `""`      |
| `safety`           | `str`  | --                 | `"manual"`|
| `replacement_text` | `str`  | `replacementText`  | `""`      |
| `offset`           | `int`  | --                 | `0`       |
| `length`           | `int`  | --                 | `0`       |

#### `Finding`

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

#### `AnalysisResult`

| Field      | Type             | JSON Alias | Default |
|------------|------------------|------------|---------|
| `run_id`   | `str`            | `runId`    | `""`    |
| `success`  | `bool`           | --         | `True`  |
| `findings` | `list[Finding]`  | --         | `[]`    |

#### `ApplyResult`

| Field            | Type        | JSON Alias      | Default |
|------------------|-------------|-----------------|---------|
| `files_modified` | `int`       | `filesModified` | `0`     |
| `fixes_applied`  | `int`       | `fixesApplied`  | `0`     |
| `fixes_skipped`  | `int`       | `fixesSkipped`  | `0`     |
| `errors`         | `list[str]` | --              | `[]`    |

### Result caching

Recent runs are retained in a simple in-memory LRU cache
(`python/astharbor_mcp/resources.py::RunCache`) with a capacity of 20. Runs
are keyed by the CLI-generated `run_id` (a hex-encoded millisecond
timestamp, e.g. `run-18f3a2b4c10`). This backing store is what
`read_finding`, the MCP resources, and the background task result plumbing
query.

### Background task manager

The `TaskManager` in `python/astharbor_mcp/tasks.py` is a thread-safe
registry of daemon worker threads. Each `Task` records:

- `task_id`, `kind`
- `status` (`pending` → `running` → `completed` | `failed`)
- `started_at`, `finished_at`
- `progress_message`
- `result` (usually a JSON string) or `error`

The manager is a module-level singleton. All tools under
"Background task tools" above delegate to it.

## Example: Claude Desktop Configuration

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

Or via the installed entry point:

```json
{
  "mcpServers": {
    "astharbor": {
      "command": "astharbor-mcp"
    }
  }
}
```
