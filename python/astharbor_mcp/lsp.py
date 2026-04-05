"""Minimal Language Server Protocol frontend for ASTHarbor.

Wraps the astharbor CLI as an LSP server over stdio. On every
textDocument/didOpen and textDocument/didSave, the server invokes
`astharbor analyze --format=json` on the URI-mapped path and publishes
the findings as LSP diagnostics.

Scope: this is intentionally minimal. We advertise full-document text
sync but do not re-analyze on didChange — the buffer state drifts from
disk between saves, and the C++ analyzer needs real compile commands
that only the on-disk file guarantees. Users see diagnostics refresh
on save, matching how most CI-oriented static analyzers integrate with
LSP clients (clang-tidy, cppcheck-lsp, etc.).

Run via:

    python -m astharbor_mcp.lsp

or via the `astharbor-lsp` entry point installed by pyproject.toml.

LSP spec reference: https://microsoft.github.io/language-server-protocol/
"""

from __future__ import annotations

import json
import logging
import sys
import urllib.parse
from typing import Any

from . import cli_bridge


log = logging.getLogger("astharbor_lsp")

# LSP severity constants (§3.17.1).
SEVERITY_ERROR = 1
SEVERITY_WARNING = 2
SEVERITY_INFORMATION = 3
SEVERITY_HINT = 4

# LSP CodeActionKind values we emit.
CODE_ACTION_KIND_QUICKFIX = "quickfix"


def _severity_to_lsp(severity: str) -> int:
    """Map ASTHarbor severity strings to LSP Diagnostic severity levels."""
    return {
        "error": SEVERITY_ERROR,
        "warning": SEVERITY_WARNING,
        "note": SEVERITY_INFORMATION,
        "info": SEVERITY_INFORMATION,
        "hint": SEVERITY_HINT,
    }.get(severity.lower(), SEVERITY_WARNING)


def _uri_to_path(uri: str) -> str:
    """Convert an LSP file:// URI to a local path."""
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "file":
        return uri
    return urllib.parse.unquote(parsed.path)


def _path_to_uri(path: str) -> str:
    return "file://" + urllib.parse.quote(path)


def _build_line_index(text: str) -> tuple[bytes, list[int]]:
    """Return a (utf-8 bytes, cumulative line-start byte offsets) pair.

    LSP 3.17 defines `character` as an offset into UTF-16 code units on
    the containing line. To convert a byte offset we need to find the
    enclosing line and then count UTF-16 units in the line prefix; both
    are cheap once we precompute the byte positions of every `\\n`.
    Built once per analyzed file, reused across every fix in the request.
    """
    encoded = text.encode("utf-8")
    line_starts = [0]
    for index, byte in enumerate(encoded):
        if byte == 0x0A:  # '\n'
            line_starts.append(index + 1)
    return encoded, line_starts


def _byte_offset_to_position(encoded: bytes, line_starts: list[int],
                              byte_offset: int) -> dict[str, int]:
    """Convert a byte offset into an LSP position using a prebuilt index."""
    clamped = max(0, min(byte_offset, len(encoded)))
    # Binary search for the last line-start <= clamped.
    import bisect
    line = bisect.bisect_right(line_starts, clamped) - 1
    line_prefix = encoded[line_starts[line]:clamped].decode("utf-8", errors="replace")
    character = len(line_prefix.encode("utf-16-le")) // 2
    return {"line": line, "character": character}


def _fix_to_code_action(fix: dict[str, Any], diagnostic: dict[str, Any],
                        uri: str, encoded: bytes,
                        line_starts: list[int]) -> dict[str, Any] | None:
    """Map one ASTHarbor fix to an LSP CodeAction with a WorkspaceEdit.

    The CLI only emits offset/length on fixes whose edits are byte-
    accurate; fixes without that metadata are silently skipped.
    """
    offset = fix.get("offset")
    length = fix.get("length")
    if offset is None or length is None:
        return None
    start = _byte_offset_to_position(encoded, line_starts, int(offset))
    end = _byte_offset_to_position(encoded, line_starts, int(offset) + int(length))
    text_edit = {
        "range": {"start": start, "end": end},
        "newText": fix.get("replacementText", ""),
    }
    title = fix.get("description") or f"ASTHarbor: {diagnostic.get('code', '')}"
    return {
        "title": title,
        "kind": CODE_ACTION_KIND_QUICKFIX,
        "diagnostics": [diagnostic],
        "edit": {"changes": {uri: [text_edit]}},
        "isPreferred": True,
    }


def _finding_to_diagnostic(finding: dict[str, Any]) -> dict[str, Any]:
    """Map an ASTHarbor finding to an LSP Diagnostic object."""
    # LSP uses 0-based positions; ASTHarbor uses 1-based. Clamp to 0 so a
    # degenerate (0,0) finding still produces a valid range.
    line = max(0, int(finding.get("line", 1)) - 1)
    column = max(0, int(finding.get("column", 1)) - 1)
    # Zero-width range anchored at the finding location. LSP clients
    # widen the highlight automatically when the user hovers.
    position = {"line": line, "character": column}
    return {
        "range": {"start": position, "end": position},
        "severity": _severity_to_lsp(finding.get("severity", "warning")),
        "source": "astharbor",
        "code": finding.get("ruleId", ""),
        "message": finding.get("message", ""),
    }


class LspServer:
    """Stdio JSON-RPC LSP server that wraps the astharbor CLI."""

    def __init__(self) -> None:
        self._running = True
        # Cache findings and file text per URI so textDocument/codeAction
        # can reuse the last didOpen/didSave analysis instead of
        # re-invoking the CLI and re-reading the file for every keystroke.
        self._findings_by_uri: dict[str, list[dict[str, Any]]] = {}
        self._text_by_uri: dict[str, str] = {}

    # ── Framing ────────────────────────────────────────────────────────

    def _read_message(self) -> dict[str, Any] | None:
        """Read one LSP message from stdin. Returns None on EOF."""
        headers: dict[str, str] = {}
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                return None
            decoded = line.decode("utf-8", errors="replace").strip()
            if not decoded:
                break
            if ": " in decoded:
                key, value = decoded.split(": ", 1)
                headers[key] = value
        length_str = headers.get("Content-Length")
        if not length_str:
            return None
        length = int(length_str)
        body = sys.stdin.buffer.read(length).decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            log.exception("Failed to parse LSP body: %r", body)
            return None

    def _write_message(self, message: dict[str, Any]) -> None:
        """Write one LSP message to stdout with proper framing."""
        body = json.dumps(message, separators=(",", ":"))
        header = f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n"
        sys.stdout.buffer.write(header.encode("utf-8"))
        sys.stdout.buffer.write(body.encode("utf-8"))
        sys.stdout.buffer.flush()

    def _respond(self, request_id: Any, result: Any = None,
                 error: dict[str, Any] | None = None) -> None:
        response: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
        if error is not None:
            response["error"] = error
        else:
            response["result"] = result
        self._write_message(response)

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._write_message({"jsonrpc": "2.0", "method": method, "params": params})

    # ── Request handlers ───────────────────────────────────────────────

    def _handle_initialize(self, request_id: Any, _params: dict[str, Any]) -> None:
        # Full-document sync (value 1). Incremental sync (2) would require
        # tracking buffer contents in Python; full sync is sufficient since
        # we only re-analyze on save.
        capabilities = {
            "textDocumentSync": {
                "openClose": True,
                "change": 1,
                "save": {"includeText": False},
            },
            "diagnosticProvider": {
                "interFileDependencies": False,
                "workspaceDiagnostics": False,
            },
            "codeActionProvider": {
                "codeActionKinds": [CODE_ACTION_KIND_QUICKFIX],
                "resolveProvider": False,
            },
        }
        self._respond(request_id, result={
            "capabilities": capabilities,
            "serverInfo": {"name": "astharbor-lsp", "version": "0.1"},
        })

    def _handle_shutdown(self, request_id: Any, _params: dict[str, Any]) -> None:
        self._respond(request_id, result=None)

    def _handle_exit(self, _request_id: Any, _params: dict[str, Any]) -> None:
        self._running = False

    # ── Notification handlers ──────────────────────────────────────────

    def _handle_did_open(self, params: dict[str, Any]) -> None:
        uri = params.get("textDocument", {}).get("uri", "")
        if not uri:
            return
        self._analyze_and_publish(uri, _uri_to_path(uri))

    def _handle_did_save(self, params: dict[str, Any]) -> None:
        uri = params.get("textDocument", {}).get("uri", "")
        if not uri:
            return
        self._analyze_and_publish(uri, _uri_to_path(uri))

    def _handle_did_close(self, params: dict[str, Any]) -> None:
        uri = params.get("textDocument", {}).get("uri", "")
        if not uri:
            return
        self._findings_by_uri.pop(uri, None)
        self._text_by_uri.pop(uri, None)
        self._notify("textDocument/publishDiagnostics",
                     {"uri": uri, "diagnostics": []})

    def _handle_code_action(self, request_id: Any, params: dict[str, Any]) -> None:
        """Return quick-fix CodeActions for findings overlapping the range.

        If the client passes `context.diagnostics`, only findings whose
        (code, start-line) pair matches one of those entries produce
        actions; otherwise every cached finding with a safe fix is
        returned.
        """
        uri = params.get("textDocument", {}).get("uri", "")
        if not uri:
            self._respond(request_id, result=[])
            return
        findings = self._findings_by_uri.get(uri, [])
        if not findings:
            self._respond(request_id, result=[])
            return
        file_text = self._text_by_uri.get(uri)
        if file_text is None:
            file_text = self._load_file_text(uri)
            if file_text is None:
                self._respond(request_id, result=[])
                return
        encoded, line_starts = _build_line_index(file_text)

        context_diagnostics = (params.get("context") or {}).get("diagnostics") or []
        wanted: set[tuple[str, int]] | None = None
        if context_diagnostics:
            wanted = {
                (str(diag.get("code", "")),
                 diag.get("range", {}).get("start", {}).get("line", -1))
                for diag in context_diagnostics
            }

        actions: list[dict[str, Any]] = []
        for finding in findings:
            diagnostic = _finding_to_diagnostic(finding)
            if wanted is not None:
                key = (str(diagnostic.get("code", "")),
                       diagnostic["range"]["start"]["line"])
                if key not in wanted:
                    continue
            for fix in finding.get("fixes", []):
                if fix.get("safety") != "safe":
                    continue
                action = _fix_to_code_action(fix, diagnostic, uri, encoded, line_starts)
                if action is not None:
                    actions.append(action)
        self._respond(request_id, result=actions)

    def _load_file_text(self, uri: str) -> str | None:
        """Read and cache the file text for a URI, returning None on IO error."""
        path = _uri_to_path(uri)
        try:
            with open(path, encoding="utf-8", errors="replace") as file_obj:
                file_text = file_obj.read()
        except OSError as exc:
            log.warning("could not read %s for code actions: %s", path, exc)
            return None
        self._text_by_uri[uri] = file_text
        return file_text

    # ── Analysis bridge ────────────────────────────────────────────────

    def _analyze_and_publish(self, uri: str, path: str) -> None:
        """Invoke the CLI on `path` and publish a diagnostics notification."""
        diagnostics: list[dict[str, Any]] = []
        cached_findings: list[dict[str, Any]] = []
        try:
            raw = cli_bridge.run_analyze(path, fmt="json")
            parsed = json.loads(raw)
            for finding in parsed.get("findings", []):
                # Only surface findings whose file matches the open URI —
                # the analyzer may also emit diagnostics from transitively-
                # included headers the client hasn't opened.
                if finding.get("file") and finding["file"] != path:
                    continue
                diagnostics.append(_finding_to_diagnostic(finding))
                cached_findings.append(finding)
        except Exception as exc:  # noqa: BLE001 — any failure should degrade gracefully
            log.warning("analyze failed for %s: %s", path, exc)
        self._findings_by_uri[uri] = cached_findings
        # Prime the file-text cache now so code-action requests don't
        # have to go to disk on the first invocation after open/save.
        self._load_file_text(uri)
        self._notify("textDocument/publishDiagnostics",
                     {"uri": uri, "diagnostics": diagnostics})

    # ── Main loop ──────────────────────────────────────────────────────

    def run(self) -> int:
        while self._running:
            message = self._read_message()
            if message is None:
                break
            method = message.get("method")
            request_id = message.get("id")
            params = message.get("params", {}) or {}

            # Requests (have an id) expect a response; notifications don't.
            if method == "initialize":
                self._handle_initialize(request_id, params)
            elif method == "initialized":
                pass  # notification, no response
            elif method == "shutdown":
                self._handle_shutdown(request_id, params)
            elif method == "exit":
                self._handle_exit(request_id, params)
                break
            elif method == "textDocument/didOpen":
                self._handle_did_open(params)
            elif method == "textDocument/didSave":
                self._handle_did_save(params)
            elif method == "textDocument/didClose":
                self._handle_did_close(params)
            elif method == "textDocument/didChange":
                pass  # we only re-analyze on save
            elif method == "textDocument/codeAction":
                self._handle_code_action(request_id, params)
            else:
                # Unknown method. Reply with MethodNotFound only if this was
                # a request; notifications silently ignore unknown methods
                # per the LSP spec.
                if request_id is not None:
                    self._respond(request_id, error={
                        "code": -32601,
                        "message": f"Method not found: {method}",
                    })
        return 0


def main() -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    return LspServer().run()


if __name__ == "__main__":
    raise SystemExit(main())
