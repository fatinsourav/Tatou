import io
import pytest

pytestmark = pytest.mark.usefixtures("app_with_db")


def test_upload_document_missing_file(client, auth_headers):
    # no "file" in form data
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data={"name": "nofile.pdf"},
        content_type="multipart/form-data",
    )
    assert r.status_code in (400, 422)
    data = r.get_json()
    assert "error" in data


def test_upload_document_invalid_name(client, auth_headers):
    # underscore should be rejected by your validation
    pdf_io = io.BytesIO(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    data = {"file": (pdf_io, "bad_name.pdf"), "name": "bad_name.pdf"}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    data = r.get_json()
    assert "error" in data
    assert "name can only contain" in data["error"] or "name" in data["error"].lower()


def test_get_document_not_found(client, auth_headers):
    # assuming 99999 is not a valid id in the test DB
    r = client.get("/api/get-document/99999", headers=auth_headers)
    assert r.status_code in (404, 400)
    data = r.get_json()
    assert "error" in data


def test_delete_document_unknown_id(client, auth_headers):
    r = client.delete("/api/delete-document/99999", headers=auth_headers)
    # could be 404 or 200 depending on implementation – but must not 500
    assert r.status_code in (200, 404)
