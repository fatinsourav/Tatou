# server/test/test_server_extra_routes.py

import io
import sys
from pathlib import Path

import pytest

import server


def test_home_and_healthz(client):
    # "/" should serve index.html (or at least not 500)
    r = client.get("/")
    assert r.status_code in (200, 304, 404)  # accept 404 if static not present

    # /healthz should return JSON and not 500
    r = client.get("/healthz")
    assert r.status_code in (200, 503)
    data = r.get_json()
    assert isinstance(data, dict)


# ---------- require_auth branches ----------

def test_require_auth_missing_header(client):
    # No Authorization header at all
    r = client.get("/api/list-documents")
    assert r.status_code == 401
    data = r.get_json()
    assert "Authorization" in data.get("error", "")


def test_require_auth_invalid_token(client):
    # Bad token that cannot be deserialized
    r = client.get(
        "/api/list-documents",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )
    assert r.status_code == 401
    data = r.get_json()
    assert "Invalid token" in data.get("error", "")


# ---------- upload-document error paths ----------

def test_upload_document_no_file(client, auth_headers):
    r = client.post("/api/upload-document", headers=auth_headers, data={})
    assert r.status_code == 400
    data = r.get_json()
    assert "file" in data.get("error", "").lower()


def test_upload_document_empty_filename(client, auth_headers):
    data = {"file": (io.BytesIO(b"dummy"), "")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    data = r.get_json()
    assert "name" in data.get("error", "").lower() or "filename" in data.get("error", "").lower()


def test_upload_document_not_pdf_extension(client, auth_headers):
    data = {"file": (io.BytesIO(b"not pdf"), "image.png")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    data = r.get_json()
    # error message mentions PDF requirement
    assert "pdf" in data.get("error", "").lower()


def test_upload_document_wrong_mimetype(client, auth_headers):
    # .pdf name but wrong content_type: server treats this as "no file" because
    # it's not proper multipart/form-data.
    data = {"file": (io.BytesIO(b"not really pdf"), "fake.pdf")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="application/octet-stream",
    )
    # Should be a client error, but not 500
    assert r.status_code in (400, 415)
    data = r.get_json()
    # Just assert that an error message is present
    assert "error" in data and data["error"]



# ---------- create-user validation & duplicates ----------

def test_create_user_missing_fields(client):
    r = client.post("/api/create-user", json={})
    assert r.status_code == 400
    data = r.get_json()
    # generic required-fields error
    assert "required" in data.get("error", "").lower()


def test_create_user_invalid_login(client):
    # login too short / invalid pattern (see server-side regex)
    r = client.post(
        "/api/create-user",
        json={
            "email": "invalid-login@example.test",
            "login": "x",  # invalid username (too short)
            "password": "pw",
        },
    )
    assert r.status_code == 400
    data = r.get_json()
    assert "username" in data.get("error", "").lower() or "login" in data.get("error", "").lower()


def test_create_user_duplicate_login_and_email(client):
    # First attempt: either creates the user or, if another test already did,
    # returns 409. Both are acceptable for the rest of this test.
    r1 = client.post(
        "/api/create-user",
        json={
            "email": "dup1@example.test",
            "login": "dupuser",
            "password": "pw1",
        },
    )
    assert r1.status_code in (200, 201, 409)

    # Same login, different email → conflict
    r2 = client.post(
        "/api/create-user",
        json={
            "email": "dup2@example.test",
            "login": "dupuser",
            "password": "pw2",
        },
    )
    assert r2.status_code == 409
    data2 = r2.get_json()
    assert "username" in data2.get("error", "").lower() or "login" in data2.get("error", "").lower()

    # Same email, different login → conflict
    r3 = client.post(
        "/api/create-user",
        json={
            "email": "dup1@example.test",
            "login": "dupuser2",
            "password": "pw3",
        },
    )
    assert r3.status_code == 409
    data3 = r3.get_json()
    assert "email" in data3.get("error", "").lower()


# ---------- login error & rate limiting (429 handler) ----------

def test_login_invalid_credentials(client):
    r = client.post(
        "/api/login",
        json={"email": "nosuch@example.test", "password": "wrong"},
    )
    # Should be 401 or 404-ish, but not 500
    assert r.status_code in (400, 401, 404)
    data = r.get_json()
    assert "invalid" in data.get("error", "").lower() or "not found" in data.get("error", "").lower()


def test_login_rate_limit_triggers_429(client):
    # Hit login several times to trigger flask-limiter
    # (limit is 3 per minute; 4th should be 429)
    for i in range(4):
        r = client.post(
            "/api/login",
            json={"email": "nosuch@example.test", "password": "wrong"},
        )

    assert r.status_code == 429
    data = r.get_json()
    assert data.get("error") == "rate_limited"
    detail = data.get("detail", "")
    assert isinstance(detail, str)
    assert detail.strip() != ""  # some human-readable rate info like "3 per 1 minute"

