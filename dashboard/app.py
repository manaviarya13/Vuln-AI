"""Interactive VulnAI static analysis dashboard."""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from scanner.ai_explainer import explain_finding
from scanner.models import ScanResult
from scanner.report_generator import generate_report
from scanner.semgrep_wrapper import ALLOWED_EXTENSIONS, MAX_FILE_BYTES, scan_paths
from scanner.severity import risk_score, severity_counts

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = PROJECT_ROOT / "examples"
MAX_UPLOADS = 20
load_dotenv(PROJECT_ROOT / ".env")


def validate_upload(name: str, data: bytes) -> tuple[str, bytes]:
    """Validate an uploaded source file and return a sanitized basename."""
    basename = Path(name.replace("\\", "/")).name
    suffix = Path(basename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Upload a Python or JavaScript source file (.py, .js, .jsx, .mjs, .cjs)."
        )
    if not data or len(data) > MAX_FILE_BYTES:
        raise ValueError(
            f"Each file must be non-empty and at most {MAX_FILE_BYTES // 1000} KB."
        )
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Files must be UTF-8 encoded text.") from exc
    return basename, data


def scan_uploads(uploaded: Sequence[tuple[str, bytes]]) -> ScanResult:
    """Write validated uploads to an isolated temporary directory and scan them."""
    if not uploaded:
        raise ValueError("Select at least one source file.")
    if len(uploaded) > MAX_UPLOADS:
        raise ValueError(f"A scan can include at most {MAX_UPLOADS} files.")
    with tempfile.TemporaryDirectory(prefix="vulnai-") as temp_dir:
        paths: list[Path] = []
        for name, data in uploaded:
            safe_name, safe_data = validate_upload(name, data)
            # Disambiguate duplicate basenames without allowing path traversal.
            target = Path(temp_dir) / safe_name
            index = 1
            while target.exists():
                target = (
                    Path(temp_dir)
                    / f"{Path(safe_name).stem}_{index}{Path(safe_name).suffix}"
                )
                index += 1
            target.write_bytes(safe_data)
            paths.append(target)
        return scan_paths(paths)


def scan_demo() -> ScanResult:
    """Scan the included vulnerable examples for an immediate demonstration."""
    return scan_paths(sorted(EXAMPLES.glob("*")))


def render(result: ScanResult) -> None:
    """Render findings, summaries, AI explanations, and downloadable reports."""
    findings = result.findings
    counts = severity_counts(item.severity for item in findings)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Files scanned", len(result.scanned_files))
    c2.metric("Potential findings", len(findings))
    c3.metric("High / Critical", counts["HIGH"] + counts["CRITICAL"])
    c4.metric("Risk score", risk_score(item.severity for item in findings))
    if result.errors:
        for error in result.errors:
            st.warning(error)
    if not findings:
        st.success("No findings reported by the configured rules.")
    for index, finding in enumerate(findings):
        title = f"{finding.severity} · {finding.type} — {finding.file}:{finding.line}"
        with st.expander(title, expanded=index == 0):
            st.write(finding.description)
            st.caption(
                f"Rule `{finding.rule_id}` · {finding.confidence} confidence · {finding.category}"
            )
            st.code(finding.code_snippet, language="text")
            st.markdown(f"**Recommendation:** {finding.recommendation}")
            if st.button("Generate AI explanation", key=f"explain-{index}"):
                st.session_state[f"explanation-{index}"] = explain_finding(finding)
            if st.session_state.get(f"explanation-{index}"):
                st.markdown(st.session_state[f"explanation-{index}"])
    col1, col2, col3 = st.columns(3)
    for col, fmt, mime in (
        (col1, "json", "application/json"),
        (col2, "csv", "text/csv"),
        (col3, "markdown", "text/markdown"),
    ):
        col.download_button(
            f"Download {fmt.upper()}",
            generate_report(result, fmt),
            file_name=f"vulnai-report.{fmt}",
            mime=mime,
        )
    st.caption(
        f"Completed in {result.duration_seconds:.2f}s. Findings are static-analysis signals, not proof of exploitability."
    )


def main() -> None:
    """Run the Streamlit application."""
    st.set_page_config(
        page_title="VulnAI · Security Scanner", page_icon="🛡️", layout="wide"
    )
    css_path = Path(__file__).with_name("styles.css")
    if css_path.exists():
        st.markdown(
            f"<style>{css_path.read_text(encoding='utf-8')}</style>",
            unsafe_allow_html=True,
        )
    st.title("🛡️ VulnAI")
    st.caption("AI-assisted static security analysis for Python and JavaScript")
    st.info(
        "Potential findings require human review. Uploaded code is analyzed locally; snippets sent to the optional AI provider are redacted."
    )
    tab_upload, tab_demo = st.tabs(["Scan source files", "Try the demo"])
    with tab_upload:
        uploads = st.file_uploader(
            "Choose source files",
            type=[ext.lstrip(".") for ext in sorted(ALLOWED_EXTENSIONS)],
            accept_multiple_files=True,
            help="UTF-8 source only; 1 MB maximum per file and 20 files per scan.",
        )
        if st.button("Scan uploaded files", type="primary", disabled=not uploads):
            try:
                with st.spinner("Running Semgrep rules..."):
                    data = [(upload.name, upload.getvalue()) for upload in uploads]
                    st.session_state["scan_result"] = scan_uploads(data)
            except ValueError as exc:
                st.error(str(exc))
    with tab_demo:
        st.write("Scan intentionally vulnerable snippets included with the project.")
        if st.button("Run demo scan", type="primary"):
            with st.spinner("Scanning bundled examples..."):
                st.session_state["scan_result"] = scan_demo()
    if isinstance(st.session_state.get("scan_result"), ScanResult):
        st.divider()
        render(st.session_state["scan_result"])


if __name__ == "__main__":
    main()
