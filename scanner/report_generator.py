"""Export scan results to JSON, CSV, or Markdown."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Literal

from scanner.models import ScanResult


def generate_report(
    result: ScanResult, fmt: Literal["json", "csv", "markdown"] = "json"
) -> str:
    """Render a scan report in the requested portable format."""
    if fmt == "json":
        return json.dumps(
            {"generated_at": datetime.now(UTC).isoformat(), **result.to_dict()},
            indent=2,
        )
    if fmt == "csv":
        output = io.StringIO(newline="")
        rows = [finding.to_dict() for finding in result.findings]
        fields = (
            list(rows[0])
            if rows
            else [
                "rule_id",
                "type",
                "category",
                "severity",
                "confidence",
                "file",
                "line",
                "end_line",
                "description",
                "recommendation",
                "code_snippet",
            ]
        )
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()
    if fmt == "markdown":
        lines = [
            "# VulnAI Scan Report",
            "",
            f"Generated: {datetime.now(UTC).isoformat()}",
            "",
            f"Files scanned: {len(result.scanned_files)}",
            f"Findings: {len(result.findings)}",
            "",
        ]
        if not result.findings:
            lines.append(
                "No findings were reported by the configured static analysis rules."
            )
        for item in result.findings:
            lines.extend(
                [
                    f"## {item.severity}: {item.type}",
                    "",
                    f"- **Location:** `{item.file}:{item.line}`",
                    f"- **Confidence:** {item.confidence}",
                    f"- **Description:** {item.description}",
                    f"- **Recommendation:** {item.recommendation}",
                    "",
                    "```text",
                    item.code_snippet,
                    "```",
                    "",
                ]
            )
        lines.extend(
            [
                "> Static analysis identifies potential issues; findings are not proof of exploitability.",
                "",
            ]
        )
        return "\n".join(lines)
    raise ValueError(f"Unsupported report format: {fmt}")
