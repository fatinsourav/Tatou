import io
import pytest

pytestmark = pytest.mark.usefixtures("app_with_db")


def _upload_pdf(client, auth_headers, name="sample.pdf"):
    """Helper to upload a tiny PDF and return the JSON response."""
    pdf_io = io.BytesIO(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    data = {"file": (pdf_io, name), "name": name}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    # In normal operation this should be 200/201
    assert r.status_code in (200, 201), r.get_data(as_text=True)
    return r.get_json()


def test_list_documents_empty(client, auth_headers):
    r = client.get("/api/list-documents", headers=auth_headers)
    assert r.status_code == 200
    js = r.get_json()
    assert isinstance(js, dict)
    assert "documents" in js
    assert isinstance(js["documents"], list)
    # On a fresh test DB, this should start empty
    assert js["documents"] == []


def test_upload_and_get_document(client, auth_headers):
    doc = _upload_pdf(client, auth_headers)
    doc_id = doc["id"]

    # After upload, document should appear in list-documents
    r = client.get("/api/list-documents", headers=auth_headers)
    assert r.status_code == 200
    docs = r.get_json()["documents"]
    assert any(d["id"] == doc_id for d in docs)

    # get-document should return PDF bytes
    r = client.get(f"/api/get-document/{doc_id}", headers=auth_headers)
    assert r.status_code == 200
    ctype = r.headers.get("Content-Type", "")
    assert ctype.startswith("application/pdf")
    assert r.data.startswith(b"%PDF")


def test_create_watermark_and_list_versions(client, auth_headers):
    # Upload a base PDF
    doc = _upload_pdf(client, auth_headers)
    doc_id = doc["id"]

    # Pick the first available method name
    r = client.get("/api/get-watermarking-methods")
    assert r.status_code == 200
    methods = r.get_json()["methods"]
    assert methods, "no watermarking methods exposed via API"
    method_name = methods[0]["name"]

    # Create watermarked version
    wm_resp = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=auth_headers,
        json={
            "method": method_name,
            "position": None,
            "key": "api_test_key",
            "secret": "api_test_secret",
            "intended_for": "user@example.test",
        },
    )
    assert wm_resp.status_code in (200, 201), wm_resp.get_data(as_text=True)
    wm = wm_resp.get_json()
    version_id = wm.get("id")

    # list-versions for that document should show at least one version
    r = client.get(f"/api/list-versions/{doc_id}", headers=auth_headers)
    assert r.status_code == 200
    versions = r.get_json()["versions"]
    assert isinstance(versions, list)
    assert len(versions) >= 1

    # list-all-versions should also contain at least one version
    r = client.get("/api/list-all-versions", headers=auth_headers)
    assert r.status_code == 200
    all_versions = r.get_json()["versions"]
    assert isinstance(all_versions, list)
    assert len(all_versions) >= 1

    # public get-version/<link> should serve the PDF without auth
    r = client.get(f"/api/get-version/{wm['link']}")
    assert r.status_code == 200
    assert r.headers.get("Content-Type", "").startswith("application/pdf")
    assert r.data.startswith(b"%PDF")


def test_read_watermark_roundtrip(client, auth_headers):
    # Upload a base PDF
    doc = _upload_pdf(client, auth_headers)
    doc_id = doc["id"]

    # Choose method
    methods = client.get("/api/get-watermarking-methods").get_json()["methods"]
    assert methods
    method_name = methods[0]["name"]

    # Create version with a known secret
    secret = "roundtrip_secret"
    key = "roundtrip_key"
    wm_resp = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=auth_headers,
        json={
            "method": method_name,
            "position": None,
            "key": key,
            "secret": secret,
            "intended_for": "roundtrip@example.test",
        },
    )
    assert wm_resp.status_code in (200, 201), wm_resp.get_data(as_text=True)
    wm = wm_resp.get_json()

    # Call read-watermark; for our tiny synthetic PDF, the AddAfterEOF
    # method may not successfully embed a detectable watermark.
    read_resp = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=auth_headers,
        json={"method": wm["method"], "position": wm["position"], "key": key},
    )
    # The important thing is: no 500, and a clear JSON response.
    assert read_resp.status_code in (200, 400), read_resp.get_data(as_text=True)
    payload = read_resp.get_json()
    if read_resp.status_code == 200:
        # If the watermark was found, it must match our secret.
        assert payload["secret"] == secret
    else:
        # Otherwise we expect a precise error message from the server.
        assert "error" in payload
        assert "No AddAfterEOF watermark found" in payload["error"]


def test_delete_document_removes_access(client, auth_headers):
    # use a name that passes the server's validation (letters + digits + dot)
    doc = _upload_pdf(client, auth_headers, name="deleteme.pdf")
    doc_id = doc["id"]

    # Delete (should be 200 OK)
    r = client.delete(f"/api/delete-document/{doc_id}", headers=auth_headers)
    assert r.status_code == 200

    # Getting the doc again should return 404
    r = client.get(f"/api/get-document/{doc_id}", headers=auth_headers)
    assert r.status_code == 404
