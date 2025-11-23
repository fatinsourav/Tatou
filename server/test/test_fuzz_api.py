import base64
import io
import os
import random
import string
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st
import yaml

# Ensure project root (where `fuzzing/` lives) is on sys.path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent  # /home/lab/Tatou/server
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fuzzing.regression_helpers import record_failure  # now importable

# ---------------------------------------------------------------------------
# Load fuzzer configuration
# ---------------------------------------------------------------------------

CONFIG_PATH = ROOT_DIR / "fuzzing" / "fuzzer_config.yaml"

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    FUZZER_CONFIG = yaml.safe_load(f)

MAX_EXAMPLES: int = int(FUZZER_CONFIG.get("max_examples", 25))
DEADLINE_MS: Optional[int] = FUZZER_CONFIG.get("deadline_ms")
if DEADLINE_MS is not None:
    DEADLINE_MS = int(DEADLINE_MS)

# ---------------------------------------------------------------------------
# Hypothesis helpers
# ---------------------------------------------------------------------------


def _random_string(min_size: int = 1, max_size: int = 32) -> st.SearchStrategy[str]:
    """Random visible ASCII string."""
    alphabet = string.ascii_letters + string.digits + "_-@."
    return st.text(alphabet=alphabet, min_size=min_size, max_size=max_size)


def _assert_not_5xx(response, context: Dict[str, Any]) -> None:
    """
    Common helper: assert that a response is not a 5xx.
    If it *is* a 5xx, we record a regression case to fuzzing/findings/.
    """
    if 500 <= response.status_code < 600:
        # Try to capture body as text but never crash if that fails
        try:
            body_text: Optional[str] = response.get_data(as_text=True)
        except Exception:
            body_text = None

        record_failure(
            base_case=context,
            status_code=response.status_code,
            response_body=body_text,
        )

    assert response.status_code < 500, (
        f"Unexpected 5xx status {response.status_code} for context={context} "
        f"body={response.get_data(as_text=True)!r}"
    )


# ---------------------------------------------------------------------------
# 1. Fuzz create-user and login
# ---------------------------------------------------------------------------


@given(
    email=_random_string(min_size=5, max_size=20).map(lambda s: s + "@example.test"),
    login=_random_string(min_size=3, max_size=16),
    password=_random_string(min_size=8, max_size=32),
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_create_user_and_login(client, email, login, password):
    # CREATE USER
    create_payload = {"email": email, "login": login, "password": password}
    r = client.post("/api/create-user", json=create_payload)
    _assert_not_5xx(
        r,
        {
            "name": "create_user",
            "method": "POST",
            "path": "/api/create-user",
            "json": create_payload,
        },
    )

    # LOGIN
    login_payload = {"email": email, "password": password}
    r = client.post("/api/login", json=login_payload)
    _assert_not_5xx(
        r,
        {
            "name": "login",
            "method": "POST",
            "path": "/api/login",
            "json": login_payload,
        },
    )

    # If login succeeded, response should contain a token
    if r.status_code == 200:
        data = r.get_json()
        assert "token" in data


# ---------------------------------------------------------------------------
# 2. Fuzz upload-document, list-documents and get-document
# ---------------------------------------------------------------------------

pdf_bytes_strategy = st.binary(min_size=0, max_size=5_000)


@given(
    filename=_random_string(min_size=3, max_size=20).map(lambda s: s + ".pdf"),
    pdf_bytes=pdf_bytes_strategy,
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_upload_and_list_get_document(client, auth_headers, filename, pdf_bytes):
    # UPLOAD
    pdf_io = io.BytesIO(pdf_bytes)
    data = {"file": (pdf_io, filename), "name": filename}

    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    upload_context: Dict[str, Any] = {
        "name": "upload_document",
        "method": "POST",
        "path": "/api/upload-document",
        "filename": filename,
        "bytes_b64": base64.b64encode(pdf_bytes).decode("ascii"),
    }
    _assert_not_5xx(r, upload_context)

    if r.status_code not in (200, 201):
        # Nothing more we can do without a valid document
        return

    doc = r.get_json()
    doc_id = doc["id"]

    # LIST
    r = client.get("/api/list-documents", headers=auth_headers)
    _assert_not_5xx(
        r,
        {
            "name": "list_documents",
            "method": "GET",
            "path": "/api/list-documents",
        },
    )

    # GET DOCUMENT
    r = client.get(f"/api/get-document/{doc_id}", headers=auth_headers)
    _assert_not_5xx(
        r,
        {
            "name": "get_document",
            "method": "GET",
            "path": "/api/get-document/<id>",
            "doc_id": doc_id,
        },
    )


# ---------------------------------------------------------------------------
# 3. Fuzz create-watermark and read-watermark
# ---------------------------------------------------------------------------

secret_strategy = _random_string(min_size=1, max_size=64)
key_strategy = _random_string(min_size=1, max_size=32)


@given(
    filename=_random_string(min_size=3, max_size=20).map(lambda s: s + ".pdf"),
    pdf_bytes=pdf_bytes_strategy,
    secret=secret_strategy,
    key=key_strategy,
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_create_and_read_watermark(
    client,
    auth_headers,
    filename,
    pdf_bytes,
    secret,
    key,
):
    # First upload a PDF (same as above)
    pdf_io = io.BytesIO(pdf_bytes)
    data = {"file": (pdf_io, filename), "name": filename}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    upload_context: Dict[str, Any] = {
        "name": "upload_document_for_watermark",
        "method": "POST",
        "path": "/api/upload-document",
        "filename": filename,
        "bytes_b64": base64.b64encode(pdf_bytes).decode("ascii"),
    }
    _assert_not_5xx(r, upload_context)

    if r.status_code not in (200, 201):
        return

    doc = r.get_json()
    doc_id = doc["id"]

    # Fetch available watermarking methods
    r_methods = client.get("/api/get-watermarking-methods", headers=auth_headers)
    _assert_not_5xx(
        r_methods,
        {
            "name": "get_watermarking_methods_for_fuzz",
            "method": "GET",
            "path": "/api/get-watermarking-methods",
        },
    )
    if r_methods.status_code != 200:
        return

    methods = r_methods.get_json().get("methods", [])
    if not methods:
        return
    method_name = methods[0]["name"]

    # CREATE WATERMARK
    wm_payload = {
        "method": method_name,
        "position": None,
        "key": key,
        "secret": secret,
        "intended_for": "fuzz@example.test",
    }
    r = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=auth_headers,
        json=wm_payload,
    )
    _assert_not_5xx(
        r,
        {
            "name": "create_watermark",
            "method": "POST",
            "path": "/api/create-watermark/<doc_id>",
            "doc_id": doc_id,
            "json": wm_payload,
        },
    )

    if r.status_code not in (200, 201):
        return

    wm = r.get_json()

    # READ WATERMARK
    read_payload = {
        "method": wm["method"],
        "position": wm["position"],
        "key": key,
    }
    r = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=auth_headers,
        json=read_payload,
    )
    _assert_not_5xx(
        r,
        {
            "name": "read_watermark",
            "method": "POST",
            "path": "/api/read-watermark/<doc_id>",
            "doc_id": doc_id,
            "json": read_payload,
        },
    )

    if r.status_code == 200:
        data = r.get_json()
        assert data.get("secret") == secret


# ---------------------------------------------------------------------------
# 4. Fuzz delete-document and list-all-versions
# ---------------------------------------------------------------------------


@given(
    filename=_random_string(min_size=3, max_size=20).map(lambda s: s + ".pdf"),
    pdf_bytes=pdf_bytes_strategy,
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_delete_document_and_list_all_versions(
    client,
    auth_headers,
    filename,
    pdf_bytes,
):
    # Upload
    pdf_io = io.BytesIO(pdf_bytes)
    data = {"file": (pdf_io, filename), "name": filename}
    r = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    upload_context: Dict[str, Any] = {
        "name": "upload_document_for_delete",
        "method": "POST",
        "path": "/api/upload-document",
        "filename": filename,
        "bytes_b64": base64.b64encode(pdf_bytes).decode("ascii"),
    }
    _assert_not_5xx(r, upload_context)

    if r.status_code not in (200, 201):
        return

    doc_id = r.get_json()["id"]

    # LIST ALL VERSIONS
    r = client.get("/api/list-all-versions", headers=auth_headers)
    _assert_not_5xx(
        r,
        {
            "name": "list_all_versions",
            "method": "GET",
            "path": "/api/list-all-versions",
        },
    )

    # DELETE DOCUMENT
    r = client.delete(f"/api/delete-document/{doc_id}", headers=auth_headers)
    _assert_not_5xx(
        r,
        {
            "name": "delete_document",
            "method": "DELETE",
            "path": "/api/delete-document/<doc_id>",
            "doc_id": doc_id,
        },
    )


# ---------------------------------------------------------------------------
# 5. Fuzz get-watermarking-methods (idempotent GET)
# ---------------------------------------------------------------------------


@given(dummy=st.integers())
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_get_watermarking_methods(client, auth_headers, dummy):
    r = client.get("/api/get-watermarking-methods", headers=auth_headers)
    _assert_not_5xx(
        r,
        {
            "name": "get_watermarking_methods",
            "method": "GET",
            "path": "/api/get-watermarking-methods",
        },
    )

    if r.status_code == 200:
        data = r.get_json()
        assert "methods" in data
        assert isinstance(data["methods"], list)
