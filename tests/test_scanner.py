"""Tests for scanner validation, normalization, and process safety."""

import json
import platform
import shutil
import subprocess

import pytest

from scanner.semgrep_wrapper import redact_snippet, scan_paths


def test_redact_secret_values() -> None:
    assert "demo-secret" not in redact_snippet('API_KEY = "demo-secret"')
    assert "ghp_" not in redact_snippet("token=ghp_1234567890abcdef")


def test_scan_rejects_unsupported_and_missing_files(tmp_path) -> None:
    bad = tmp_path / "notes.txt"
    bad.write_text("no", encoding="utf-8")
    result = scan_paths([bad, tmp_path / "absent.py"])
    assert result.findings == []
    assert len(result.errors) == 2


def test_missing_semgrep_is_reported(tmp_path, monkeypatch) -> None:
    source = tmp_path / "sample.py"
    source.write_text("print('ok')", encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setattr("scanner.semgrep_wrapper.shutil.which", lambda _name: None)
    result = scan_paths([source], rules_dir=rules)
    assert not result.findings
    assert any("not installed" in error for error in result.errors)


def test_scan_parses_semgrep_json_and_redacts(tmp_path, monkeypatch) -> None:
    source = tmp_path / "sample.py"
    source.write_text('password = "do-not-show-this"\n', encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir()
    output = {
        "results": [
            {
                "check_id": "vulnai.python.hardcoded-secret",
                "path": str(source),
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "WARNING",
                    "metadata": {"confidence": "HIGH"},
                    "message": "Credential literal",
                    "lines": 'password = "do-not-show-this"',
                },
            }
        ]
    }

    def fake_run(command, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["timeout"] > 0
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    monkeypatch.setattr("scanner.semgrep_wrapper.subprocess.run", fake_run)
    result = scan_paths([source], semgrep_bin="semgrep", rules_dir=rules)
    assert len(result.findings) == 1
    assert result.findings[0].severity == "MEDIUM"
    assert "do-not-show-this" not in result.findings[0].code_snippet


def test_semgrep_timeout_is_handled(tmp_path, monkeypatch) -> None:
    source = tmp_path / "sample.py"
    source.write_text("print('ok')", encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir()

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr("scanner.semgrep_wrapper.subprocess.run", timeout)
    result = scan_paths([source], semgrep_bin="semgrep", rules_dir=rules, timeout=1)
    assert any("timeout" in error.lower() for error in result.errors)


@pytest.mark.skipif(
    platform.system() == "Windows" or not shutil.which("semgrep"),
    reason="Semgrep integration requires a working non-Windows Semgrep runtime",
)
def test_bundled_examples_produce_all_expected_categories() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    result = scan_paths(sorted((root / "examples").glob("*")))
    categories = {finding.type for finding in result.findings}
    assert {"SQL Injection", "Cross-Site Scripting", "Hardcoded Secret"} <= categories
