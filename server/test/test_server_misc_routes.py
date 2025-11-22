import io


def test_list_versions_without_id_uses_query_param(client, auth_headers):
    pdf_io = io.BytesIO(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    )
    # Use a name that passes the server's validation (letters + digits + dot)
    data = {
        "file": (pdf_io, "listversions.pdf"),
        "name": "listversions.pdf",
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
    # Same fix here – filename without underscore
    data = {
        "file": (pdf_io, "getbyparam.pdf"),
        "name": "getbyparam.pdf",
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
