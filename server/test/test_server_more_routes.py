import io
import base64
import json

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


def _create_watermark(client, auth_headers, doc_id, intended_for="user@example.test"):
    # Get methods
    r = client.get("/api/get-watermarking-methods")
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
            "key": "more-tests-key",
            "secret": "more-tests-secret",
            "intended_for": intended_for,
        },
    )
    assert r.status_code in (200, 201)
    return r.get_json()


def test_list_versions_requires_document_id(client, auth_headers):
    # No id -> should be 400
    r = client.get("/api/list-versions", headers=auth_headers)
    assert r.status_code == 400
    data = r.get_json()
    assert "document id required" in data.get("error", "").lower()


def test_list_all_versions_after_creating_one(client, auth_headers):
    # Upload document and create a watermark
    doc = _upload_pdf(client, auth_headers)
    doc_id = doc["id"]
    _create_watermark(client, auth_headers, doc_id)

    # list-all-versions should return a JSON list (maybe filtered by server logic)
    r = client.get("/api/list-all-versions", headers=auth_headers)
    assert r.status_code == 200
    payload = r.get_json()
    assert "versions" in payload
    versions = payload["versions"]
    assert isinstance(versions, list)
    # If any version is present, it should at least have an id field
    if versions:
        assert "id" in versions[0]



def test_get_document_requires_id_if_not_in_path(client, auth_headers):
    r = client.get("/api/get-document", headers=auth_headers)
    assert r.status_code == 400
    data = r.get_json()
    assert "document id required" in data.get("error", "").lower()


def test_rmap_initiate_missing_payload(client):
    r = client.post("/api/rmap-initiate", json={})
    assert r.status_code == 400
    data = r.get_json()
    assert "missing 'payload'" in data.get("error", "").lower()


def test_rmap_get_link_missing_payload(client):
    r = client.post("/api/rmap-get-link", json={})
    assert r.status_code == 400
    data = r.get_json()
    assert "missing 'payload'" in data.get("error", "").lower()
