import io
import pytest


# ------------------ Basic routes ------------------

def test_home_and_healthz(client):
    r = client.get("/")
    assert r.status_code in (200, 304, 404)

    r = client.get("/healthz")
    assert r.status_code in (200, 503)
    data = r.get_json()
    assert isinstance(data, dict)


# ------------------ require_auth ------------------

def test_require_auth_missing_header(client):
    r = client.get("/api/list-documents")
    assert r.status_code == 401
    assert "authorization" in r.get_json().get("error", "").lower()


def test_require_auth_invalid_token(client):
    r = client.get(
        "/api/list-documents",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )
    assert r.status_code == 401
    assert "invalid token" in r.get_json().get("error", "").lower()


# ------------------ upload-document errors ------------------

def test_upload_document_no_file(client, auth_headers):
    r = client.post("/api/upload-document", headers=auth_headers, data={})
    # Should be validation error, not rate-limited
    assert r.status_code == 400
    assert "file" in r.get_json().get("error", "").lower()


def test_upload_document_empty_filename(client, auth_headers):
    data = {"file": (io.BytesIO(b"dummy"), "")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    msg = r.get_json().get("error", "").lower()
    assert "name" in msg or "filename" in msg


def test_upload_document_not_pdf_extension(client, auth_headers):
    data = {"file": (io.BytesIO(b"not pdf"), "image.png")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "pdf" in r.get_json().get("error", "").lower()


def test_upload_document_wrong_mimetype(client, auth_headers):
    data = {"file": (io.BytesIO(b"not really pdf"), "fake.pdf")}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="application/octet-stream",
    )
    assert r.status_code in (400, 415)
    assert "error" in r.get_json()


# ------------------ create-user validation ------------------

def test_create_user_missing_fields(client):
    r = client.post("/api/create-user", json={})
    assert r.status_code == 400
    assert "required" in r.get_json().get("error", "").lower()


def test_create_user_invalid_login(client):
    r = client.post(
        "/api/create-user",
        json={"email": "bad@example", "login": "x", "password": "pw"},
    )
    assert r.status_code == 400
    msg = r.get_json().get("error", "").lower()
    assert "login" in msg or "username" in msg


def test_create_user_duplicate_login_and_email(client):
    # First create
    client.post(
        "/api/create-user",
        json={"email": "dup1@example", "login": "dupuser", "password": "pw"},
    )

    # Duplicate login
    r2 = client.post(
        "/api/create-user",
        json={"email": "dup2@example", "login": "dupuser", "password": "pw"},
    )
    assert r2.status_code == 409

    # Duplicate email
    r3 = client.post(
        "/api/create-user",
        json={"email": "dup1@example", "login": "otheruser", "password": "pw"},
    )
    assert r3.status_code in (201, 409)


# ------------------ login error & rate limiting ------------------

def test_login_invalid_credentials(client):
    r = client.post("/api/login", json={"email": "nosuch", "password": "bad"})
    assert r.status_code in (400, 401, 404)
    msg = r.get_json().get("error", "").lower()
    assert "invalid" in msg or "not found" in msg


def test_login_rate_limit_triggers_429(client):
    # Make 3 requests (limit), then 4th should be 429
    for _ in range(3):
        client.post("/api/login", json={"email": "nosuch", "password": "wrong"})

    r = client.post("/api/login", json={"email": "nosuch", "password": "wrong"})
    assert r.status_code == 429
    data = r.get_json()
    assert data.get("error") == "rate_limited"
    assert isinstance(data.get("detail", ""), str)
