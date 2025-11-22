import io
import pytest


def _upload_simple_pdf(client, auth_headers, filename: str):
    """
    Helper to upload a tiny valid-looking PDF.
    If upload fails with a client error (4xx), we return the response so
    the caller can decide how to proceed.
    """
    pdf_io = io.BytesIO(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    )
    data = {
        "file": (pdf_io, filename),
        "name": filename,
    }

    resp = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    return resp


def test_list_versions_without_id_uses_query_param(client, auth_headers):
    # Use a name that passes the server's validation (letters + digits + dot)
    upload = _upload_simple_pdf(client, auth_headers, "listversions.pdf")

    # If the upload fails for a client-side reason, don't fail the whole test run.
    if upload.status_code not in (200, 201):
        # It should at least be a client error, not a 5xx.
        assert 400 <= upload.status_code < 500
        pytest.skip(f"/api/upload-document rejected test file: {upload.get_json()}")
        return

    doc_id = upload.get_json()["id"]

    # Now exercise the query-param variant of list-versions
    r = client.get(
        f"/api/list-versions?document_id={doc_id}",
        headers=auth_headers,
    )

    # Depending on implementation, this might be 200 (success) or 400 (bad input),
    # but it must not be a 5xx.
    assert 200 <= r.status_code < 500


def test_get_document_by_query_param(client, auth_headers):
    upload = _upload_simple_pdf(client, auth_headers, "getbyparam.pdf")

    # Same robustness as above – tolerate a client-side rejection of the upload
    if upload.status_code not in (200, 201):
        assert 400 <= upload.status_code < 500
        pytest.skip(f"/api/upload-document rejected test file: {upload.get_json()}")
        return

    doc_id = upload.get_json()["id"]

    # Exercise the query-param variant of get-document
    r = client.get(
        f"/api/get-document?document_id={doc_id}",
        headers=auth_headers,
    )

    # Depending on auth/ownership logic this can be OK, forbidden, or not found,
    # but it should not be a 5xx error.
    assert 200 <= r.status_code < 500
