"""Safe Semgrep CLI wrapper and finding normalization."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from scanner.models import Finding, ScanResult
from scanner.severity import normalize_severity

MAX_FILE_BYTES = 1_000_000
ALLOWED_EXTENSIONS = {".py", ".js", ".jsx", ".mjs", ".cjs"}
SECRET_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|token|password|passwd|secret|credential|private[_-]?key)\b\s*[:=]\s*)(['\"])[^'\"]+\2"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b"
)


def redact_snippet(text: str) -> str:
    """Redact common credential assignments and token formats."""
    return SECRET_VALUE_RE.sub("[REDACTED]", SECRET_RE.sub(r"\1\2[REDACTED]\2", text))


def _category(rule_id: str) -> tuple[str, str, str]:
    lower = rule_id.lower()
    if "secret" in lower or "credential" in lower:
        return (
            "Hardcoded Secret",
            "Secrets Management",
            "Move credentials to environment variables or a secrets manager; rotate exposed credentials.",
        )
    if "sql" in lower or "injection" in lower:
        return (
            "SQL Injection",
            "Injection",
            "Use parameterized queries and avoid constructing SQL with untrusted string values.",
        )
    if "xss" in lower or "innerhtml" in lower or "dom" in lower:
        return (
            "Cross-Site Scripting",
            "Cross-Site Scripting",
            "Use textContent or context-aware output encoding for untrusted values.",
        )
    return (
        "Security Issue",
        "Other",
        "Review the data flow and apply the secure API recommended by the relevant framework.",
    )


def _finding(raw: dict[str, Any], root: Path) -> Finding:
    rule = raw.get("check_id", "unknown")
    metadata = raw.get("extra", {}).get("metadata", {})
    issue_type, category, recommendation = _category(rule)
    path = Path(raw.get("path", "unknown"))
    try:
        display_path = str(path.resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        display_path = path.name
    start = raw.get("start", {})
    end = raw.get("end", {})
    extra = raw.get("extra", {})
    snippet = redact_snippet(str(extra.get("lines", ""))).strip()
    return Finding(
        rule_id=rule,
        type=issue_type,
        category=category,
        severity=normalize_severity(metadata.get("severity") or extra.get("severity")),
        confidence=str(metadata.get("confidence", "MEDIUM")).upper(),
        file=display_path,
        line=int(start.get("line", 1)),
        end_line=int(end.get("line", start.get("line", 1))),
        description=str(
            extra.get(
                "message", "Potential security issue detected by static analysis."
            )
        ),
        recommendation=recommendation,
        code_snippet=snippet or "[source context unavailable]",
    )


def scan_paths(
    paths: Iterable[str | Path],
    *,
    semgrep_bin: str | None = None,
    timeout: int = 90,
    rules_dir: str | Path | None = None,
) -> ScanResult:
    """Scan validated local Python/JavaScript files using bundled custom rules."""
    started = time.monotonic()
    root = Path.cwd()
    files: list[Path] = []
    errors: list[str] = []
    for item in paths:
        path = Path(item)
        try:
            if not path.is_file() or path.suffix.lower() not in ALLOWED_EXTENSIONS:
                errors.append(f"Skipped unsupported or missing file: {path.name}")
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                errors.append(f"Skipped file over {MAX_FILE_BYTES} bytes: {path.name}")
                continue
            files.append(path.resolve())
        except OSError:
            errors.append(f"Could not read file: {path.name}")
    result = ScanResult(scanned_files=[file.name for file in files], errors=errors)
    if not files:
        result.duration_seconds = time.monotonic() - started
        return result
    binary = semgrep_bin or shutil.which("semgrep") or shutil.which("semgrep.exe")
    if not binary:
        result.errors.append(
            "Semgrep is not installed. Install the project requirements to enable scanning."
        )
        result.duration_seconds = time.monotonic() - started
        return result
    config = Path(rules_dir) if rules_dir else Path(__file__).parent / "rules"
    if not config.exists():
        result.errors.append(f"Custom Semgrep rules directory not found: {config}")
        result.duration_seconds = time.monotonic() - started
        return result
    command = [
        binary,
        "scan",
        "--config",
        str(config),
        "--json",
        "--no-git-ignore",
        "--quiet",
        *map(str, files),
    ]
    try:
        process_env = os.environ.copy()
        process_env["SEMGREP_SEND_METRICS"] = "off"
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env=process_env,
        )
        if completed.returncode not in (0, 1):
            result.errors.append(
                f"Semgrep exited with code {completed.returncode}: {completed.stderr.strip()[:500]}"
            )
        if completed.stdout.strip():
            payload = json.loads(completed.stdout)
            result.findings = [
                _finding(item, root) for item in payload.get("results", [])
            ]
    except subprocess.TimeoutExpired:
        result.errors.append(f"Semgrep scan exceeded the {timeout}-second timeout.")
    except (OSError, json.JSONDecodeError) as exc:
        result.errors.append(f"Semgrep could not complete or return valid JSON: {exc}")
    result.duration_seconds = time.monotonic() - started
    return result
