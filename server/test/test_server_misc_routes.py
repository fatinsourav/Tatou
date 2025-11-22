# test/test_server_misc_routes.py

import io


def test_healthz_endpoint(client):
    # Hit /healthz; allow 200 or 503 depending on DB state, but not 500
    r = client.get("/healthz")
    assert r.status_code in (200, 503)
    data = r.get_json()
    assert isinstance(data, dict)


def test_root_index_or_404(client):
    # Root path may be 200 (landing page) or 404; just ensure no 500
    r = client.get("/")
    assert r.status_code in (200, 404)


def test_unknown_path_404(client):
    r = client.get("/this-path-definitely-does-not-exist-xyz")
    assert r.status_code == 404


def test_list_versions_without_id_uses_query_param(client, auth_headers):
    # Upload a document first
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

    # Call /api/list-versions using ?document_id= instead of /<id>
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
    # Could be 200 (file), 403, or 404 depending on access checks – but not 500
    assert r.status_code in (200, 403, 404)
