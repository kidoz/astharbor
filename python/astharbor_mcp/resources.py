"""MCP resource endpoints for cached analysis runs."""

from __future__ import annotations

import json
from collections import OrderedDict

from .models import AnalysisResult


MAX_CACHED_RUNS = 20


class RunCache:
    """LRU cache of recent analysis runs for follow-up resource reads."""

    def __init__(self, max_size: int = MAX_CACHED_RUNS):
        self._cache: OrderedDict[str, AnalysisResult] = OrderedDict()
        self._max_size = max_size

    def store(self, result: AnalysisResult) -> str:
        """Store an analysis result and return its run_id."""
        run_id = result.run_id
        if run_id in self._cache:
            self._cache[run_id] = result
            self._cache.move_to_end(run_id)
        else:
            self._cache[run_id] = result
            if len(self._cache) > self._max_size:
                self._cache.popitem(last=False)
        return run_id

    def get(self, run_id: str) -> AnalysisResult | None:
        """Retrieve a cached run by ID."""
        result = self._cache.get(run_id)
        if result is not None:
            self._cache.move_to_end(run_id)
        return result

    def get_summary(self, run_id: str) -> dict | None:
        """Get a summary of a cached run."""
        result = self.get(run_id)
        if result is None:
            return None
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for finding in result.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        return {
            "runId": result.run_id,
            "success": result.success,
            "totalFindings": len(result.findings),
            "bySeverity": severity_counts,
            "byCategory": category_counts,
        }

    def get_finding_by_id(self, run_id: str, finding_id: str) -> dict | None:
        """Get a specific finding from a cached run by stable findingId."""
        result = self.get(run_id)
        if result is None:
            return None
        for finding in result.findings:
            if finding.finding_id == finding_id:
                return json.loads(finding.model_dump_json(by_alias=True))
        return None

    def get_finding(self, run_id: str, identifier: int | str) -> dict | None:
        """Get a finding by stable findingId, with index fallback for legacy callers."""
        result = self.get(run_id)
        if result is None:
            return None

        if isinstance(identifier, str):
            by_id = self.get_finding_by_id(run_id, identifier)
            if by_id is not None:
                return by_id
            if not identifier.isdigit():
                return None
            index = int(identifier)
        else:
            index = identifier

        if index < 0 or index >= len(result.findings):
            return None
        finding = result.findings[index]
        return json.loads(finding.model_dump_json(by_alias=True))

    def list_runs(self) -> list[str]:
        """List all cached run IDs (most recent last)."""
        return list(self._cache.keys())


# Singleton cache instance
cache = RunCache()
