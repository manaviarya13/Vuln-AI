"""Typed data models shared by scanning, explaining, and reporting code."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Finding:
    """A normalized, potential security issue returned by static analysis."""

    rule_id: str
    type: str
    category: str
    severity: str
    confidence: str
    file: str
    line: int
    end_line: int
    description: str
    recommendation: str
    code_snippet: str
    ai_explanation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable copy of this finding."""
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    """Result of a single scan, including operational errors if any."""

    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable result."""
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "scanned_files": self.scanned_files,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }
