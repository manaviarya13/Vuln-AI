"""Tests for the dashboard's upload validation boundary."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from dashboard.app import validate_upload


def test_upload_filename_is_reduced_to_basename() -> None:
    name, content = validate_upload("../../folder/source.py", b"print('ok')")
    assert name == "source.py"
    assert content == b"print('ok')"


@pytest.mark.parametrize(
    "name,data", [("code.exe", b"x"), ("code.py", b"\xff"), ("code.js", b"")]
)
def test_invalid_uploads_rejected(name: str, data: bytes) -> None:
    with pytest.raises(ValueError):
        validate_upload(name, data)


def test_dashboard_renders_without_errors() -> None:
    app_file = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    app = AppTest.from_file(str(app_file)).run()
    assert not app.exception
    assert {button.label for button in app.button} >= {
        "Scan uploaded files",
        "Run demo scan",
    }
