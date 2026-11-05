"""Tests for JSON, CSV, and Markdown report exports."""

import csv
import io
import json

from scanner.models import Finding, ScanResult
from scanner.report_generator import generate_report


def test_report_formats() -> None:
    result = ScanResult(
        findings=[
            Finding(
                "rule",
                "SQL Injection",
                "Injection",
                "HIGH",
                "MEDIUM",
                "a.py",
                3,
                3,
                "Unsafe query",
                "Use parameters",
                "cursor.execute(query)",
            )
        ],
        scanned_files=["a.py"],
    )
    assert json.loads(generate_report(result, "json"))["findings"][0]["line"] == 3
    assert (
        next(csv.DictReader(io.StringIO(generate_report(result, "csv"))))["severity"]
        == "HIGH"
    )
    assert "SQL Injection" in generate_report(result, "markdown")


def test_empty_csv_has_header() -> None:
    assert "rule_id" in generate_report(ScanResult(), "csv")
