# ASTHarbor

ASTHarbor is a production-ready MVP of a Clang-first C/C++ code analyzer. It is designed to be easily extensible, respects real project build settings, and suggests safe fixes. It provides a CLI for immediate use and is AI-agent-friendly via a FastMCP server.

## Architecture Overview

- **Core Analyzer (C++23)**: Built with Meson and utilizes Clang LibTooling and AST Matchers to parse and analyze code deterministically based on `compile_commands.json` or direct compiler flags.
- **CLI Frontend (C++)**: The main binary (`astharbor`) interacts with the core to analyze files, list rules, apply fixes, and report on toolchains.
- **MCP Frontend (Python 3.14)**: A FastMCP server (`astharbor_mcp`) that wraps the CLI. It exposes tools and resources for AI agents to interact with the analyzer, invoking the CLI as a subprocess and exchanging structured JSON.

## Build Instructions

ASTHarbor requires LLVM/Clang (version 14 or higher) and Meson.

```bash
# Set compilers and specify the build directory
CXX=clang++ CC=clang meson setup build

# Compile the project
meson compile -C build

# Run C++ tests
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

```bash
# Analyze a single file and output as text
astharbor analyze examples/cpp_sample/main.cpp --

# Analyze a single file and output as JSON
astharbor analyze examples/cpp_sample/main.cpp --format=json --

# List all available rules
astharbor rules

# View toolchain doctor report
astharbor doctor
```

## MCP Server Usage Examples

The MCP server allows AI agents to interact with ASTHarbor. Start the server using FastMCP:

```bash
# Inside the python directory with the venv activated
fastmcp run astharbor_mcp.server:mcp
```

## Example JSON Output

When running `astharbor analyze --format=json`, the output looks like this:

```json
{
  "runId": "run-123",
  "findings": [
    {
      "findingId": "",
      "ruleId": "modernize/use-nullptr",
      "severity": "warning",
      "message": "Use nullptr instead of NULL",
      "category": "modernize",
      "file": "/path/to/main.cpp",
      "line": 2,
      "column": 14,
      "fixes": []
    }
  ]
}
```

## Example Fix Preview

*(Fix preview output in text mode is currently a WIP for v0)*
```
Finding: modernize/use-nullptr in main.cpp:2:14
Message: Use nullptr instead of NULL
Suggested Fix: Replace `NULL` with `nullptr` (safe)
```

## How to add a new rule

1. Create a new header in `src/rules/` inheriting from `astharbor::Rule`.
2. Override `id()`, `title()`, `category()`, `summary()`, and `defaultSeverity()`.
3. Implement `registerMatchers(clang::ast_matchers::MatchFinder &Finder)` to bind your AST Matchers.
4. Implement `run(const clang::ast_matchers::MatchFinder::MatchResult &Result)` to extract matched nodes and append findings to `this->findings`.
5. Register your rule in `src/core/rule_registry.cpp` within `registerBuiltinRules()`.

See `docs/rules.md` for more details.
