import io
import pytest


def _tiny_pdf():
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


def _upload_pdf(client, auth_headers, name="sample.pdf"):
    pdf_io = io.BytesIO(_tiny_pdf())
    data = {"file": (pdf_io, name), "name": name}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert r.status_code in (200, 201)
    return r.get_json()


def _create_watermark(client, auth_headers, doc_id):
    # Get methods
    r = client.get("/api/get-watermarking-methods", headers=auth_headers)
    assert r.status_code == 200
    methods = r.get_json()["methods"]
    assert methods

    method_name = methods[0]["name"]

    r = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=auth_headers,
        json={
            "method": method_name,
            "position": None,
            "key": "wmkey",
            "secret": "wmsecret",
            "intended_for": "me@example",
        },
    )
    assert r.status_code in (200, 201)
    return r.get_json()


# ------------------ list-versions ------------------

def test_list_versions_requires_document_id(client, auth_headers):
    r = client.get("/api/list-versions", headers=auth_headers)
    assert r.status_code == 400
    assert "document id required" in r.get_json().get("error", "").lower()


# ------------------ list-all-versions ------------------

def test_list_all_versions_after_creating_one(client, auth_headers):
    doc = _upload_pdf(client, auth_headers)
    doc_id = doc["id"]
    _create_watermark(client, auth_headers, doc_id)

    r = client.get("/api/list-all-versions", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "versions" in data
    assert isinstance(data["versions"], list)


# ------------------ get-document ------------------

def test_get_document_requires_id_if_not_in_path(client, auth_headers):
    r = client.get("/api/get-document", headers=auth_headers)
    assert r.status_code == 400
    assert "document id required" in r.get_json().get("error", "").lower()


# ------------------ rmap ------------------

def test_rmap_initiate_missing_payload(client):
    r = client.post("/api/rmap-initiate", json={})
    assert r.status_code == 400
    assert "missing 'payload'" in r.get_json().get("error", "").lower()


def test_rmap_get_link_missing_payload(client):
    r = client.post("/api/rmap-get-link", json={})
    assert r.status_code == 400
    assert "missing 'payload'" in r.get_json().get("error", "").lower()
