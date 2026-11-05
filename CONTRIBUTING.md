# Contributing

Thanks for helping improve VulnAI. Keep changes focused, explain security assumptions, and avoid adding real credentials or intentionally dangerous behavior outside the `examples/` directory.

## Development setup

1. Install Python 3.10 or newer.
2. Create a virtual environment and install `requirements-dev.txt`.
3. Run `ruff check scanner dashboard tests` and `python -m pytest -q`.
4. For rule changes, run the dashboard demo and confirm findings include the expected file and line.

## Security rule contributions

- Give each rule a stable `vulnai.<language>.<issue>` ID.
- Include severity, confidence, CWE metadata, and a useful remediation message.
- Prefer narrow patterns that can be reviewed and tested with a safe positive and negative example.
- Do not describe a static match as proof of exploitability.
- Ensure examples use synthetic values and never real secrets.

## Pull requests

Describe the behavior changed, security impact, and validation performed. Do not include user source code, credentials, or generated reports containing sensitive data.
