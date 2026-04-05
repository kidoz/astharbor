"""End-to-end tests for the astharbor LSP server.

These tests drive the LSP server directly (no subprocess) by calling its
message handlers and verifying the resulting notifications. Capture-based
tests of the stdio framing layer live at the bottom of the file.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import Any

from astharbor_mcp import lsp

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
EXAMPLE_FILE = os.path.join(REPO_ROOT, "examples/cpp_sample/main.cpp")


class CapturingServer(lsp.LspServer):
    """LspServer subclass that captures outgoing messages instead of
    writing them to stdout, so tests can assert on the exchange."""

    def __init__(self) -> None:
        super().__init__()
        self.sent: list[dict[str, Any]] = []

    def _write_message(self, message: dict[str, Any]) -> None:  # type: ignore[override]
        self.sent.append(message)


def test_severity_mapping():
    assert lsp._severity_to_lsp("error") == lsp.SEVERITY_ERROR
    assert lsp._severity_to_lsp("warning") == lsp.SEVERITY_WARNING
    assert lsp._severity_to_lsp("note") == lsp.SEVERITY_INFORMATION
    assert lsp._severity_to_lsp("unknown") == lsp.SEVERITY_WARNING


def test_uri_roundtrip():
    uri = lsp._path_to_uri("/tmp/foo bar.cpp")
    assert uri.startswith("file://")
    assert lsp._uri_to_path(uri) == "/tmp/foo bar.cpp"


def test_finding_to_diagnostic_converts_positions():
    finding = {
        "line": 5,
        "column": 10,
        "severity": "warning",
        "ruleId": "modernize/use-nullptr",
        "message": "Use nullptr instead of NULL",
    }
    diagnostic = lsp._finding_to_diagnostic(finding)
    # LSP is 0-based; ASTHarbor is 1-based.
    assert diagnostic["range"]["start"] == {"line": 4, "character": 9}
    assert diagnostic["range"]["end"] == {"line": 4, "character": 9}
    assert diagnostic["severity"] == lsp.SEVERITY_WARNING
    assert diagnostic["source"] == "astharbor"
    assert diagnostic["code"] == "modernize/use-nullptr"


def test_initialize_returns_capabilities():
    server = CapturingServer()
    server._handle_initialize(request_id=1, _params={})
    assert len(server.sent) == 1
    response = server.sent[0]
    assert response["id"] == 1
    caps = response["result"]["capabilities"]
    assert "textDocumentSync" in caps
    assert caps["textDocumentSync"]["openClose"] is True
    assert caps["textDocumentSync"]["save"]["includeText"] is False


def test_shutdown_returns_null():
    server = CapturingServer()
    server._handle_shutdown(request_id=2, _params={})
    assert server.sent[0]["result"] is None


def test_did_open_publishes_diagnostics_for_real_file(tmp_path):
    # Copy the example file into tmp so diagnostics reference a clean path.
    source = tmp_path / "main.cpp"
    shutil.copy(EXAMPLE_FILE, source)
    uri = lsp._path_to_uri(str(source))

    server = CapturingServer()
    server._handle_did_open({
        "textDocument": {"uri": uri, "languageId": "cpp", "version": 1, "text": ""},
    })

    # Exactly one publishDiagnostics notification should be emitted.
    notifications = [msg for msg in server.sent
                     if msg.get("method") == "textDocument/publishDiagnostics"]
    assert len(notifications) == 1
    params = notifications[0]["params"]
    assert params["uri"] == uri
    # The sample file triggers modernize/use-nullptr.
    rule_ids = [d["code"] for d in params["diagnostics"]]
    assert "modernize/use-nullptr" in rule_ids


def test_did_save_republishes_diagnostics(tmp_path):
    source = tmp_path / "main.cpp"
    shutil.copy(EXAMPLE_FILE, source)
    uri = lsp._path_to_uri(str(source))

    server = CapturingServer()
    server._handle_did_open({
        "textDocument": {"uri": uri, "languageId": "cpp", "version": 1, "text": ""},
    })
    server.sent.clear()
    server._handle_did_save({"textDocument": {"uri": uri}})

    notifications = [msg for msg in server.sent
                     if msg.get("method") == "textDocument/publishDiagnostics"]
    assert len(notifications) == 1
    assert notifications[0]["params"]["uri"] == uri


def test_did_close_clears_diagnostics(tmp_path):
    source = tmp_path / "main.cpp"
    shutil.copy(EXAMPLE_FILE, source)
    uri = lsp._path_to_uri(str(source))

    server = CapturingServer()
    server._handle_did_open({
        "textDocument": {"uri": uri, "languageId": "cpp", "version": 1, "text": ""},
    })
    server.sent.clear()
    server._handle_did_close({"textDocument": {"uri": uri}})

    notifications = [msg for msg in server.sent
                     if msg.get("method") == "textDocument/publishDiagnostics"]
    assert len(notifications) == 1
    params = notifications[0]["params"]
    assert params["uri"] == uri
    assert params["diagnostics"] == []
