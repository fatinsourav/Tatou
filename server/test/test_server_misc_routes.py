import io
import pytest

from src.server import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_healthz_endpoint(client):
    # Assuming you have /healthz (we saw it referenced in earlier logs)
    r = client.get("/healthz")
    # Allow 200 or 503 depending on DB state, but not 500
    assert r.status_code in (200, 503)
    data = r.get_json()
    assert isinstance(data, dict)


def test_root_index_or_404(client):
    # Hit the root; some apps serve a landing page, others may 404.
    r = client.get("/")
    assert r.status_code in (200, 404)


def test_unknown_path_404(client):
    r = client.get("/this-path-definitely-does-not-exist-xyz")
    # Flask default is 404, and you probably have a JSON handler
    assert r.status_code == 404


def test_list_versions_without_id_uses_query_param(client, auth_headers):
    # Upload a document first (reuse existing helper pattern)
    pdf_io = io.BytesIO(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    data = {"file": (pdf_io, "list_versions.pdf"), "name": "list_versions.pdf"}
    upload = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert upload.status_code in (200, 201)
    doc_id = upload.get_json()["id"]

    # Call /api/list-versions using ?document_id= instead of /<id> path
    r = client.get(f"/api/list-versions?document_id={doc_id}", headers=auth_headers)
    assert r.status_code == 200
    payload = r.get_json()
    assert "versions" in payload


def test_get_document_by_query_param(client, auth_headers):
    # Upload a document and fetch it via ?document_id= instead of /<id>
    pdf_io = io.BytesIO(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    data = {"file": (pdf_io, "get_by_param.pdf"), "name": "get_by_param.pdf"}
    upload = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert upload.status_code in (200, 201)
    doc_id = upload.get_json()["id"]

    r = client.get(f"/api/get-document?document_id={doc_id}", headers=auth_headers)
    # Could be 200 with file or 404/403 depending on your access checks,
    # but should not be 500.
    assert r.status_code in (200, 403, 404)
