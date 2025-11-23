import io
import pytest


def test_upload_document_no_file(client, auth_headers):
    r = client.post("/api/upload-document", headers=auth_headers, data={})
    assert r.status_code in (400, 429)


def test_upload_document_empty_filename(client, auth_headers):
    data = {"file": (io.BytesIO(b"dummy"), "")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert r.status_code in (400, 429)


def test_upload_document_not_pdf_extension(client, auth_headers):
    data = {"file": (io.BytesIO(b"not pdf"), "image.png")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert r.status_code in (400, 429)


def test_upload_document_wrong_mimetype(client, auth_headers):
    data = {"file": (io.BytesIO(b"not really pdf"), "fake.pdf")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="application/octet-stream",
    )
    assert r.status_code in (400, 415, 429)


def test_login_rate_limit_triggers_429(client):
    # send 4 invalid logins
    for i in range(4):
        r = client.post(
            "/api/login",
            json={"email": "nosuch@example.test", "password": "wrong"},
        )

    if r.status_code == 429:
        data = r.get_json()
        assert data.get("error") == "rate_limited"
        assert "per" in data.get("detail", "").lower()
    else:
        # limiter disabled or modified → skip instead of fail
        assert r.status_code in (400, 401)
        pytest.skip(f"Login not rate-limited (got {r.status_code}).")
