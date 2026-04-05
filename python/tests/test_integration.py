"""End-to-end integration tests running the astharbor binary on fixture
projects. These tests invoke the subprocess directly (via cli_bridge) so we
exercise the real binary, the JSON emitter, and the fix application pipeline.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from astharbor_mcp import cli_bridge

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
INTEGRATION_DIR = os.path.join(REPO_ROOT, "tests/integration")
CPP_FIXTURE = os.path.join(INTEGRATION_DIR, "cpp_fixture")
C_FIXTURE = os.path.join(INTEGRATION_DIR, "c_fixture")


def _run_analyze(path: str) -> dict:
    """Invoke astharbor analyze on a fixture file and return parsed JSON."""
    executable = cli_bridge.get_astharbor_path()
    result = subprocess.run(
        [executable, "analyze", path, "--format=json", "--"],
        capture_output=True,
        text=True,
    )
    # Exit 1 = findings present, 0 = clean, 2+ = operational failure
    assert result.returncode in (0, 1), (
        f"astharbor exited {result.returncode}\nstderr: {result.stderr}"
    )
    return json.loads(result.stdout)


def _rule_ids(data: dict) -> set[str]:
    return {f["ruleId"] for f in data["findings"]}


# ── C++ fixture ────────────────────────────────────────────────────────


def test_cpp_fixture_runs_successfully():
    data = _run_analyze(os.path.join(CPP_FIXTURE, "main.cpp"))
    assert data["success"] is True
    assert len(data["findings"]) > 0


def test_cpp_fixture_reports_expected_rules():
    data = _run_analyze(os.path.join(CPP_FIXTURE, "main.cpp"))
    ids = _rule_ids(data)
    expected = {
        "modernize/use-nullptr",
        "modernize/use-override",
        "readability/use-using-alias",
        "ub/division-by-zero-literal",
        "ub/static-array-oob-constant",
        "ub/new-delete-array-mismatch",
        "best-practice/no-raw-new-delete",
        "best-practice/explicit-single-arg-ctor",
    }
    missing = expected - ids
    assert not missing, f"Expected rules not found in C++ fixture: {missing}"


def test_cpp_fixture_findings_have_stable_ids():
    data = _run_analyze(os.path.join(CPP_FIXTURE, "main.cpp"))
    ids = [f["findingId"] for f in data["findings"]]
    assert all(fid.startswith("finding-") for fid in ids)
    assert len(set(ids)) == len(ids), "findingIds must be unique"


def test_cpp_fixture_produces_safe_autofixes():
    data = _run_analyze(os.path.join(CPP_FIXTURE, "main.cpp"))
    safe_rules = {
        finding["ruleId"]
        for finding in data["findings"]
        for fix in finding["fixes"]
        if fix["safety"] == "safe"
    }
    # Known safe-autofix rules that the fixture should trigger.
    assert "modernize/use-nullptr" in safe_rules
    assert "modernize/use-override" in safe_rules
    assert "readability/use-using-alias" in safe_rules
    assert "ub/new-delete-array-mismatch" in safe_rules


# ── C fixture ──────────────────────────────────────────────────────────


def test_c_fixture_runs_successfully():
    data = _run_analyze(os.path.join(C_FIXTURE, "main.c"))
    assert data["success"] is True
    assert len(data["findings"]) > 0


def test_c_fixture_reports_expected_rules():
    data = _run_analyze(os.path.join(C_FIXTURE, "main.c"))
    ids = _rule_ids(data)
    expected = {
        "security/no-gets",
        "security/no-strcpy-strcat",
        "security/no-atoi-atol-atof",
        "ub/division-by-zero-literal",
    }
    missing = expected - ids
    assert not missing, f"Expected rules not found in C fixture: {missing}"


def test_c_fixture_does_not_trigger_cxx_only_rules():
    data = _run_analyze(os.path.join(C_FIXTURE, "main.c"))
    ids = _rule_ids(data)
    # C++-specific rules should not fire on a .c file.
    assert "modernize/use-nullptr" not in ids
    assert "modernize/use-override" not in ids
    assert "portability/vla-in-cxx" not in ids


# ── Fix workflow end-to-end ────────────────────────────────────────────


def test_fix_apply_rewrites_cpp_fixture(tmp_path):
    source = tmp_path / "main.cpp"
    shutil.copy(os.path.join(CPP_FIXTURE, "main.cpp"), source)

    executable = cli_bridge.get_astharbor_path()
    # Apply only the safe nullptr fix so we can assert a deterministic change.
    result = subprocess.run(
        [executable, "fix", str(source), "--apply", "--rule=use-nullptr", "--"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    text = source.read_text()
    assert "nullptr" in text
    # Original NULL usage should have been replaced (the macro define stays,
    # but the cast site no longer uses the macro expansion).
    assert "int *pointer = nullptr" in text


def test_save_run_and_load_via_run_id(tmp_path):
    source = tmp_path / "main.cpp"
    shutil.copy(os.path.join(CPP_FIXTURE, "main.cpp"), source)
    save_path = tmp_path / "run.json"

    executable = cli_bridge.get_astharbor_path()
    # Save the run to an explicit path so the test is hermetic.
    analyze = subprocess.run(
        [
            executable,
            "analyze",
            str(source),
            f"--save-run={save_path}",
            "--format=json",
            "--",
        ],
        capture_output=True,
        text=True,
    )
    assert analyze.returncode in (0, 1)
    assert save_path.exists(), "--save-run did not create the target file"

    saved = json.loads(save_path.read_text())
    assert "runId" in saved
    assert len(saved["findings"]) > 0
    # All findings should have stable identifiers.
    assert all(f["findingId"].startswith("finding-") for f in saved["findings"])
