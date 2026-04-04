"""CLI bridge: locate and invoke the astharbor binary as a subprocess."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from .models import AnalysisResult, ApplyResult


def get_astharbor_path() -> str:
    """Find the astharbor executable in PATH or known build directories."""
    path = shutil.which("astharbor")
    if path:
        return path
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    for build_dir in ["buildDir", "builddir", "build_new", "build"]:
        candidate = os.path.join(repo_root, build_dir, "astharbor")
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(
        "Could not find 'astharbor' executable in PATH or build directories."
    )


def run_cli(*args: str) -> str:
    """Run the astharbor CLI and return stdout.

    Raises RuntimeError on exit code >= 2 (operational failure).
    Exit code 1 (findings present) is not an error.
    """
    executable = get_astharbor_path()
    result = subprocess.run(
        [executable, *args], capture_output=True, text=True
    )
    if result.returncode >= 2:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(
            f"astharbor failed (exit code {result.returncode}):\n{detail}"
        )
    return result.stdout


def run_analyze(path: str, fmt: str = "json", extra_args: str = "") -> str:
    """Run analysis on a file or directory."""
    args = ["analyze", path, f"--format={fmt}"]
    if extra_args:
        args.extend(extra_args.split())
    args.append("--")
    return run_cli(*args)


def run_analyze_json(path: str) -> AnalysisResult:
    """Run analysis and return parsed result model."""
    raw = run_analyze(path, fmt="json")
    data = json.loads(raw)
    return AnalysisResult.model_validate(data)


def run_fix_preview(path: str, rule: str = "") -> str:
    """Preview fixes for a file."""
    args = ["fix", path, "--dry-run", "--format=json"]
    if rule:
        args.append(f"--rule={rule}")
    args.append("--")
    return run_cli(*args)


def run_fix_apply(path: str, rule: str = "", backup: bool = True) -> str:
    """Apply safe fixes to a file."""
    args = ["fix", path, "--apply", "--format=json"]
    if rule:
        args.append(f"--rule={rule}")
    if backup:
        args.append("--backup")
    args.append("--")
    return run_cli(*args)


def run_rules(fmt: str = "text") -> str:
    """List all available rules."""
    return run_cli("rules", f"--format={fmt}")


def run_rules_json() -> list[dict]:
    """List rules and return parsed JSON."""
    raw = run_rules(fmt="json")
    return json.loads(raw)


def run_doctor(fmt: str = "text") -> str:
    """Run doctor command."""
    return run_cli("doctor", f"--format={fmt}")


def run_doctor_json() -> dict:
    """Run doctor and return parsed JSON."""
    raw = run_doctor(fmt="json")
    return json.loads(raw)
