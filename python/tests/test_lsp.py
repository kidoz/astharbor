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


def test_initialize_advertises_code_action_provider():
    server = CapturingServer()
    server._handle_initialize(request_id=10, _params={})
    caps = server.sent[0]["result"]["capabilities"]
    assert "codeActionProvider" in caps
    assert "quickfix" in caps["codeActionProvider"]["codeActionKinds"]


def test_byte_offset_to_position_ascii():
    text = "line0\nline1\nline2\n"
    # Offset 0 is at the start of line 0.
    assert lsp._byte_offset_to_position(text, 0) == {"line": 0, "character": 0}
    # Offset 6 is right after the first newline → start of line 1.
    assert lsp._byte_offset_to_position(text, 6) == {"line": 1, "character": 0}
    # Mid-line offsets.
    assert lsp._byte_offset_to_position(text, 9) == {"line": 1, "character": 3}


def test_byte_offset_to_position_non_ascii():
    # "αβγ" is 3 UTF-16 code units but 6 UTF-8 bytes.
    text = "αβγX\n"
    # Offset 6 is right before the 'X' (after 3 two-byte chars).
    position = lsp._byte_offset_to_position(text, 6)
    assert position == {"line": 0, "character": 3}


def test_code_action_returns_quickfix_for_safe_fix(tmp_path):
    source = tmp_path / "main.cpp"
    shutil.copy(EXAMPLE_FILE, source)
    uri = lsp._path_to_uri(str(source))

    server = CapturingServer()
    server._handle_did_open({
        "textDocument": {"uri": uri, "languageId": "cpp", "version": 1, "text": ""},
    })
    # At least one cached finding should have been stored.
    assert server._findings_by_uri.get(uri)
    server.sent.clear()

    # Request code actions for the entire file; no context diagnostics so
    # every cached finding with a safe fix should be returned.
    server._handle_code_action(request_id=99, params={
        "textDocument": {"uri": uri},
        "range": {"start": {"line": 0, "character": 0},
                   "end": {"line": 9999, "character": 0}},
        "context": {"diagnostics": []},
    })

    assert len(server.sent) == 1
    actions = server.sent[0]["result"]
    assert actions, "expected at least one code action for the nullptr fix"
    nullptr_actions = [a for a in actions
                       if any(d.get("code") == "modernize/use-nullptr"
                              for d in a.get("diagnostics", []))]
    assert nullptr_actions
    action = nullptr_actions[0]
    assert action["kind"] == "quickfix"
    edit = action["edit"]["changes"][uri][0]
    assert edit["newText"] == "nullptr"
    # Every edit range must be well-formed (start <= end).
    assert edit["range"]["start"]["line"] <= edit["range"]["end"]["line"]


def test_code_action_filters_by_context_diagnostics(tmp_path):
    source = tmp_path / "main.cpp"
    shutil.copy(EXAMPLE_FILE, source)
    uri = lsp._path_to_uri(str(source))

    server = CapturingServer()
    server._handle_did_open({
        "textDocument": {"uri": uri, "languageId": "cpp", "version": 1, "text": ""},
    })
    server.sent.clear()

    # Context with a diagnostic whose code does not match anything.
    server._handle_code_action(request_id=100, params={
        "textDocument": {"uri": uri},
        "range": {"start": {"line": 0, "character": 0},
                   "end": {"line": 9999, "character": 0}},
        "context": {"diagnostics": [{
            "code": "does-not-exist",
            "range": {"start": {"line": 0, "character": 0},
                       "end": {"line": 0, "character": 0}},
        }]},
    })
    assert server.sent[0]["result"] == []


def test_code_action_without_prior_analysis_is_empty(tmp_path):
    source = tmp_path / "main.cpp"
    shutil.copy(EXAMPLE_FILE, source)
    uri = lsp._path_to_uri(str(source))

    server = CapturingServer()
    # Deliberately skip did_open — no cached findings.
    server._handle_code_action(request_id=101, params={
        "textDocument": {"uri": uri},
        "range": {"start": {"line": 0, "character": 0},
                   "end": {"line": 0, "character": 0}},
        "context": {"diagnostics": []},
    })
    assert server.sent[0]["result"] == []
