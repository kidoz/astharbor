"""Pydantic models for ASTHarbor MCP typed tool inputs/outputs."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Fix(BaseModel):
    fix_id: str = Field(alias="fixId", default="")
    description: str = ""
    safety: str = "manual"
    replacement_text: str = Field(alias="replacementText", default="")
    offset: int = 0
    length: int = 0

    model_config = {"populate_by_name": True}


class Finding(BaseModel):
    finding_id: str = Field(alias="findingId", default="")
    rule_id: str = Field(alias="ruleId", default="")
    severity: str = ""
    category: str = ""
    message: str = ""
    file: str = ""
    line: int = 0
    column: int = 0
    fixes: list[Fix] = []

    model_config = {"populate_by_name": True}


class AnalysisResult(BaseModel):
    run_id: str = Field(alias="runId", default="")
    success: bool = True
    findings: list[Finding] = []

    model_config = {"populate_by_name": True}


class ApplyResult(BaseModel):
    files_modified: int = Field(alias="filesModified", default=0)
    fixes_applied: int = Field(alias="fixesApplied", default=0)
    fixes_skipped: int = Field(alias="fixesSkipped", default=0)
    errors: list[str] = []

    model_config = {"populate_by_name": True}
