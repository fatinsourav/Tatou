import json
import pytest
from flask import Flask, g, request

from src.flag_detection import mask_flag_in_text, detect_flag_attempt


@pytest.fixture
def app():
    app = Flask(__name__)
    app.secret_key = "test-secret"
    return app


def test_mask_flag_in_text_no_flag():
    masked, found = mask_flag_in_text("just some text")
    assert masked == "just some text"
    assert found is False


def test_mask_flag_in_text_with_flag():
    text = "Here is a FLAG{super-secret-flag-value}"
    masked, found = mask_flag_in_text(text)

    assert found is True
    assert "FLAG{" in masked
    assert "super-secret-flag-value" not in masked
    assert "len=" in masked  # from the masking format


def test_detect_flag_attempt_no_suspicious_data(app):
    with app.test_request_context("/normal", query_string={"q": "hello"}):
        detect_flag_attempt()
        assert getattr(g, "flag_attempt", False) is False


def test_detect_flag_attempt_suspicious_path_and_param(app, capsys):
    # Path starts with /flag and param name hinting at a flag
    headers = {"User-Agent": "test-agent"}
    with app.test_request_context("/flag/try", query_string={"flag": "FLAG{ctf-flag}"}, headers=headers):
        detect_flag_attempt()
        assert g.flag_attempt is True
        event = g.flag_attempt_event
        assert event["risk_level"] == "high"
        assert "path" in event
        assert event["path"].startswith("/flag")
        assert any(s["param"] == "flag" for s in event["details"]["samples"])

        # logger.warning logs a JSON event to stdout; ensure it's valid JSON
        out = capsys.readouterr().out.strip()
        if out:
            json.loads(out)


def test_detect_flag_attempt_header_and_cookie(app):
    headers = {"X-Flag": "FLAG{from-header}"}
    with app.test_request_context("/test", headers=headers):
        # Simulate a cookie manually
        request.cookies = {"session": "FLAG{cookie-flag}"}
        detect_flag_attempt()

        assert g.flag_attempt is True
        event = g.flag_attempt_event
        where = event["details"]["where"]
        assert any("header" in w or "cookie" in w for w in where)
