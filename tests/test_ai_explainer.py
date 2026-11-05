"""Tests for AI fallback and defensive prompt handling."""

from scanner.ai_explainer import explain_finding
from scanner.models import Finding


def sample() -> Finding:
    return Finding(
        "rule",
        "Hardcoded Secret",
        "Secrets Management",
        "HIGH",
        "MEDIUM",
        "x.py",
        1,
        1,
        "Credential literal",
        "Use env",
        'API_KEY = "sk-super-secret-value"',
    )


def test_fallback_when_credentials_missing(monkeypatch) -> None:
    monkeypatch.delenv("HF_API_TOKEN", raising=False)
    monkeypatch.delenv("HF_MODEL_ID", raising=False)
    explanation = explain_finding(sample())
    assert "Corrected example" in explanation
    assert "Remediation priority" in explanation


def test_provider_failure_falls_back_and_redacts_prompt() -> None:
    class Response:
        def raise_for_status(self):
            raise RuntimeError("not expected")

    class Session:
        def post(self, *args, **kwargs):
            assert "super-secret-value" not in kwargs["json"]["messages"][1]["content"]
            raise __import__("requests").Timeout("timeout")

    explanation = explain_finding(
        sample(), token="token", model_id="model", session=Session()
    )
    assert "Potential hardcoded secret" in explanation
