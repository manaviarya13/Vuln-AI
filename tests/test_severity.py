"""Tests for normalized severity and risk summaries."""

from scanner.severity import normalize_severity, risk_score, severity_counts


def test_normalize_severity() -> None:
    assert normalize_severity("error") == "HIGH"
    assert normalize_severity("WARNING") == "MEDIUM"
    assert normalize_severity("unknown") == "INFO"


def test_counts_and_score() -> None:
    assert severity_counts(["HIGH", "WARNING", "INFO"]) == {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 0,
        "INFO": 1,
    }
    assert risk_score(["HIGH", "LOW"]) == 8
