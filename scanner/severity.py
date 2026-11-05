"""Severity normalization and simple scan risk summaries."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def normalize_severity(value: str | None) -> str:
    """Normalize Semgrep severity strings into VulnAI's five-level scale."""
    normalized = (value or "INFO").strip().upper()
    normalized = {"ERROR": "HIGH", "WARNING": "MEDIUM"}.get(normalized, normalized)
    return normalized if normalized in SEVERITY_ORDER else "INFO"


def severity_counts(values: Iterable[str]) -> dict[str, int]:
    """Count severity labels, including zero-count categories."""
    counts = Counter(normalize_severity(value) for value in values)
    return {severity: counts[severity] for severity in SEVERITY_ORDER}


def risk_score(values: Iterable[str]) -> int:
    """Return a capped, weighted score suitable for dashboard display."""
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    return min(100, sum(weights[normalize_severity(value)] for value in values))
