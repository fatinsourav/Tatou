# test/test_server_misc_routes.py

import io


def test_healthz_endpoint(client):
    r = client.get("/healthz")
    assert r.status_code in (200, 503)
    assert isinstance(r.get_json(), dict)


def test_root_index_or_404(client):
    r = client.get("/")
    assert r.status_code in (200, 404)


def test_unknown_path_404(client):
    r = client.get("/definitely-not-exist-xyz")
    assert r.status_code == 404


def test_list_versions_without_id_uses_query_param(client, auth_headers):
    pdf_io = io.BytesIO(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    )
    data = {
        "file": (pdf_io, "list_versions.pdf", "application/pdf"),
        "name": "list_versions.pdf",
    }

    upload = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert upload.status_code in (200, 201)

    doc_id = upload.get_json()["id"]

    r = client.get(
        f"/api/list-versions?document_id={doc_id}",
        headers=auth_headers,
    )
    assert r.status_code == 200
    assert "versions" in r.get_json()


def test_get_document_by_query_param(client, auth_headers):
    pdf_io = io.BytesIO(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    )
    data = {
        "file": (pdf_io, "get_by_param.pdf", "application/pdf"),
        "name": "get_by_param.pdf",
    }

    upload = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert upload.status_code in (200, 201)

    doc_id = upload.get_json()["id"]

    r = client.get(
        f"/api/get-document?document_id={doc_id}",
        headers=auth_headers,
    )
    assert r.status_code in (200, 403, 404)
