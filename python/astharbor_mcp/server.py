"""ASTHarbor FastMCP server — exposes tools and resources for AI agents."""

from __future__ import annotations

import json

from fastmcp import FastMCP

from . import cli_bridge, tasks
from .models import AnalysisResult
from .resources import cache

mcp = FastMCP("ASTHarbor")


# ── Tools ──────────────────────────────────────────────────────────────


@mcp.tool()
def analyze_file(path: str) -> str:
    """Analyze a single C/C++ file and return structured JSON results."""
    result = cli_bridge.run_analyze_json(path)
    cache.store(result)
    return result.model_dump_json(by_alias=True, indent=2)


@mcp.tool()
def analyze_project(directory: str, checks: str = "") -> str:
    """Analyze all files in a project directory using its compilation database."""
    extra_args = f"--checks={checks}" if checks else ""
    raw = cli_bridge.run_analyze(directory, fmt="json", extra_args=extra_args)
    parsed = json.loads(raw)
    result = AnalysisResult.model_validate(parsed)
    cache.store(result)
    return result.model_dump_json(by_alias=True, indent=2)


@mcp.tool()
def list_rules() -> str:
    """List all available analysis rules."""
    return cli_bridge.run_rules(fmt="text")


@mcp.tool()
def list_rules_json() -> str:
    """List all available rules with metadata as JSON."""
    rules = cli_bridge.run_rules_json()
    return json.dumps(rules, indent=2)


@mcp.tool()
def preview_fix(path: str, rule: str = "") -> str:
    """Preview available fixes for a file without applying them."""
    raw = cli_bridge.run_fix_preview(path, rule=rule)
    try:
        parsed = json.loads(raw)
        return json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        return raw


@mcp.tool()
def apply_fix(path: str, confirm: bool, rule: str = "", backup: bool = True) -> str:
    """Apply safe fixes to a file. Requires confirm=True as a safety gate."""
    if not confirm:
        return "Error: confirm must be True to apply fixes. This is a safety gate."
    raw = cli_bridge.run_fix_apply(path, rule=rule, backup=backup)
    try:
        parsed = json.loads(raw)
        return json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        return raw


@mcp.tool()
def analyze_changed_files(directory: str) -> str:
    """Analyze only git-changed files in a project directory."""
    raw = cli_bridge.run_analyze_changed(directory, fmt="json")
    parsed = json.loads(raw)
    result = AnalysisResult.model_validate(parsed)
    cache.store(result)
    return result.model_dump_json(by_alias=True, indent=2)


@mcp.tool()
def analyze_incremental(directory: str) -> str:
    """Incremental analysis — only re-analyze TUs whose source or headers changed."""
    raw = cli_bridge.run_analyze_incremental(directory, fmt="json")
    parsed = json.loads(raw)
    result = AnalysisResult.model_validate(parsed)
    cache.store(result)
    return result.model_dump_json(by_alias=True, indent=2)


@mcp.tool()
def explain_rule(rule_id: str) -> str:
    """Return detailed metadata for a specific rule: what it detects,
    its severity, category, and comparable checks in other tools."""
    rules = cli_bridge.run_rules_json()
    for rule in rules:
        if rule.get("id") == rule_id:
            return json.dumps(rule, indent=2)
    return f"Error: rule '{rule_id}' not found. Use list_rules_json() to see available rules."


@mcp.tool()
def doctor_toolchains() -> str:
    """Run doctor command to verify toolchain health."""
    return cli_bridge.run_doctor(fmt="text")


@mcp.tool()
def read_finding(run_id: str, finding_index: int) -> str:
    """Read a specific finding from a cached analysis run."""
    finding = cache.get_finding(run_id, finding_index)
    if finding is None:
        return f"Error: finding not found (run_id={run_id}, index={finding_index})"
    return json.dumps(finding, indent=2)


# ── Background task tools ──────────────────────────────────────────────


@mcp.tool()
def start_background_analysis(directory: str, checks: str = "", jobs: int = 1) -> str:
    """Kick off analyze_project in the background. Returns a task id that
    callers can poll via `get_task_status` and `get_task_result`."""
    task_id = tasks.manager.start(
        "analyze_project",
        tasks.analyze_project_worker,
        directory=directory,
        checks=checks,
        jobs=jobs,
    )
    return json.dumps({"taskId": task_id, "status": "started"}, indent=2)


@mcp.tool()
def get_task_status(task_id: str) -> str:
    """Return the current status of a background task."""
    status = tasks.manager.status_dict(task_id)
    if status is None:
        return f"Error: task not found: {task_id}"
    return json.dumps(status, indent=2)


@mcp.tool()
def get_task_result(task_id: str) -> str:
    """Return the final JSON result of a completed background task."""
    task = tasks.manager.get(task_id)
    if task is None:
        return f"Error: task not found: {task_id}"
    if task.status == "failed":
        return f"Error: task {task_id} failed: {task.error}"
    if task.status != "completed":
        return f"Task {task_id} still {task.status}; poll `get_task_status` until it finishes."
    return tasks.manager.result_json(task_id) or ""


@mcp.tool()
def list_background_tasks() -> str:
    """List all background tasks seen this session."""
    return json.dumps(tasks.manager.list_tasks(), indent=2)


# ── Resources ──────────────────────────────────────────────────────────


@mcp.resource("run://{run_id}/summary")
def run_summary(run_id: str) -> str:
    """Summary of a cached analysis run."""
    summary = cache.get_summary(run_id)
    if summary is None:
        return f"Error: run {run_id} not found in cache"
    return json.dumps(summary, indent=2)


@mcp.resource("finding://{run_id}/{index}")
def finding_detail(run_id: str, index: int) -> str:
    """Detailed view of a specific finding from a cached run."""
    finding = cache.get_finding(run_id, index)
    if finding is None:
        return f"Error: finding not found (run_id={run_id}, index={index})"
    return json.dumps(finding, indent=2)


@mcp.resource("rule://{rule_id}")
def rule_detail(rule_id: str) -> str:
    """Metadata for a specific rule."""
    rules = cli_bridge.run_rules_json()
    for rule in rules:
        if rule.get("id") == rule_id:
            return json.dumps(rule, indent=2)
    return f"Error: rule {rule_id} not found"


# ── Entry point ────────────────────────────────────────────────────────


def main():
    mcp.run()


if __name__ == "__main__":
    main()
