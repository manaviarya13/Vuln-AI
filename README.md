# VulnAI

VulnAI is a Streamlit dashboard for reviewing potential security issues in Python and JavaScript source. It runs local Semgrep rules for hardcoded credentials, SQL injection patterns, and unsafe HTML sinks. Findings can be explained with an optional Hugging Face Inference Providers model and exported as JSON, CSV, or Markdown.

> Semgrep findings are static-analysis signals, not proof of exploitability. VulnAI is not a complete SAST product and does not provide comprehensive CVE detection. Always review data flow and validate remediation.

## Features

- Local custom Semgrep rules; no source upload to a scanning service.
- Upload validation for UTF-8 Python/JavaScript files, with a 1 MB per-file limit and 20-file scan limit.
- Secret redaction for displayed snippets and source sent to the optional AI provider.
- Deterministic explanations when no AI token is configured or the provider fails.
- Vulnerable built-in examples for a one-click dashboard demonstration.
- JSON, CSV, and Markdown report downloads.

## Run locally

Use Python 3.10 or newer (Python 3.12 is used in Docker and CI).

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
streamlit run dashboard/app.py
```

Open the local Streamlit URL shown in the terminal and choose **Try the demo** to scan the included examples. Semgrep is installed with the project requirements. If it is missing, the dashboard reports that condition and still remains usable for viewing prior results.

## Optional AI explanations

Copy `.env.example` to `.env`, then set `HF_API_TOKEN` and `HF_MODEL_ID` to a Hugging Face Inference Providers token and an instruction-tuned chat model available to your account. VulnAI uses Hugging Face's OpenAI-compatible chat completions endpoint. The provider may have availability, rate limits, or usage charges. If configuration is absent or the service fails, category-specific local explanations are used.

AI output is advisory and can be inaccurate. Uploaded source is treated as untrusted data; generated text is never executed. Secret-like assignments and common token formats are redacted from snippets before they are shown or sent for explanation.

## Docker

```sh
docker compose up --build
```

Then open `http://localhost:8501`. To enable AI, create a local `.env` from `.env.example` before starting. Docker Compose does not publish that file.

## Run tests and checks

```sh
python -m pytest -q
ruff check scanner dashboard tests
```

## Architecture

```text
dashboard/app.py       Streamlit UI and safe upload staging
scanner/semgrep_wrapper.py  CLI invocation, validation, normalization, redaction
scanner/rules/         Local Semgrep rules, grouped by vulnerability category
scanner/ai_explainer.py     Optional explanations and deterministic fallback
scanner/report_generator.py JSON, CSV, and Markdown exports
tests/                 Unit tests for scanner, AI fallback, reports, and upload validation
```

## Security and operational notes

- Only Python and JavaScript source extensions are accepted. Files are staged in a temporary directory and removed after the scan.
- Semgrep runs without a shell and with a time limit. Uploads are bounded by count and size.
- The current rules are intentionally focused and can produce false positives or miss issues. They do not establish exploitability or inspect dependencies for CVEs.
- Local scanning does not send source to an external service. Choosing AI explanation sends the normalized finding details and redacted code snippet to Hugging Face.
- Rotate any real secret that has been committed to source control; redaction does not remove it from repository history.

## CI

GitHub Actions installs development dependencies, runs Ruff and pytest, and builds the Docker image for pushes and pull requests targeting `main`. Set repository protections and deployment credentials separately if you want gated releases or hosted deployment.
