"""Tests for ASTHarbor MCP server tools."""

import json
import os
import time

from astharbor_mcp.server import (
    analyze_file,
    analyze_project,
    list_rules,
    list_rules_json,
    preview_fix,
    apply_fix,
    doctor_toolchains,
    read_finding,
    start_background_analysis,
    get_task_status,
    get_task_result,
    list_background_tasks,
)
from astharbor_mcp.resources import cache

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
EXAMPLE_FILE = os.path.join(REPO_ROOT, "examples/cpp_sample/main.cpp")


def test_list_rules():
    result = list_rules()
    assert "modernize/use-nullptr" in result


def test_list_rules_json():
    result = list_rules_json()
    parsed = json.loads(result)
    assert isinstance(parsed, list)
    rule_ids = [rule["id"] for rule in parsed]
    assert "modernize/use-nullptr" in rule_ids


def test_analyze_file():
    raw = analyze_file(EXAMPLE_FILE)
    result = json.loads(raw)
    assert result["success"] is True
    rule_ids = [finding["ruleId"] for finding in result["findings"]]
    assert "modernize/use-nullptr" in rule_ids


def test_analyze_file_caches_run():
    cache._cache.clear()
    raw = analyze_file(EXAMPLE_FILE)
    result = json.loads(raw)
    run_id = result["runId"]
    assert cache.get(run_id) is not None


def test_preview_fix():
    raw = preview_fix(EXAMPLE_FILE)
    parsed = json.loads(raw)
    assert "findings" in parsed
    fixes = [fix for finding in parsed["findings"] for fix in finding.get("fixes", [])]
    assert len(fixes) > 0
    assert fixes[0]["safety"] == "safe"


def test_apply_fix_requires_confirm():
    result = apply_fix(EXAMPLE_FILE, confirm=False)
    assert "confirm must be True" in result


def test_doctor_toolchains():
    result = doctor_toolchains()
    assert "ASTHarbor Doctor" in result


def test_read_finding_from_cache():
    cache._cache.clear()
    raw = analyze_file(EXAMPLE_FILE)
    result = json.loads(raw)
    run_id = result["runId"]
    finding_raw = read_finding(run_id, 0)
    finding = json.loads(finding_raw)
    assert finding["ruleId"] == "modernize/use-nullptr"


def test_read_finding_invalid():
    result = read_finding("nonexistent-run", 0)
    assert "Error" in result


# ── Background task tools ──────────────────────────────────────────────


def _wait_for_task(task_id: str, timeout_seconds: float = 10.0) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        status_json = get_task_status(task_id)
        status = json.loads(status_json)
        if status["status"] in ("completed", "failed"):
            return status
        time.sleep(0.05)
    raise TimeoutError(f"Task {task_id} did not finish within {timeout_seconds}s")


def test_start_background_analysis_returns_task_id():
    response = start_background_analysis(EXAMPLE_FILE)
    parsed = json.loads(response)
    assert "taskId" in parsed
    assert parsed["status"] == "started"
    assert parsed["taskId"].startswith("task-")


def test_background_task_completes_and_returns_result():
    response = start_background_analysis(EXAMPLE_FILE)
    task_id = json.loads(response)["taskId"]

    status = _wait_for_task(task_id)
    assert status["status"] == "completed"
    assert status["hasResult"] is True

    result_json = get_task_result(task_id)
    result = json.loads(result_json)
    assert result["success"] is True
    rule_ids = [f["ruleId"] for f in result["findings"]]
    assert "modernize/use-nullptr" in rule_ids


def test_get_task_status_for_unknown_id():
    response = get_task_status("task-does-not-exist")
    assert "Error" in response


def test_list_background_tasks_includes_started():
    response = start_background_analysis(EXAMPLE_FILE)
    task_id = json.loads(response)["taskId"]
    _wait_for_task(task_id)

    tasks_list = json.loads(list_background_tasks())
    assert any(t["taskId"] == task_id for t in tasks_list)
