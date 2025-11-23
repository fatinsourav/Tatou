import io
import json
import os
import random
import string
from typing import Optional

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

import yaml

# ---------------------------------------------------------------------------
# Load fuzzer configuration
# ---------------------------------------------------------------------------

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "fuzzing", "fuzzer_config.yaml"
)

try:
    with open(CONFIG_PATH, "r") as f:
        FUZZER_CONFIG = yaml.safe_load(f) or {}
except FileNotFoundError:
    FUZZER_CONFIG = {}

# Safe defaults if keys are missing
MAX_EXAMPLES = int(FUZZER_CONFIG.get("max_examples", 20))
DEADLINE_MS = FUZZER_CONFIG.get("deadline_ms", 1000)
MAX_PDF_BYTES = int(FUZZER_CONFIG.get("max_pdf_bytes", 4096))
MAX_TEXT_LENGTH = int(FUZZER_CONFIG.get("max_text_length", 40))

# ---------------------------------------------------------------------------
# Helper strategies and functions
# ---------------------------------------------------------------------------


def random_ascii(min_size: int = 1, max_size: int = MAX_TEXT_LENGTH) -> st.SearchStrategy:
    """Strategy for simple ASCII-ish strings (no newlines) suitable for JSON fields."""
    alphabet = string.ascii_letters + string.digits + " ._-"
    return st.text(alphabet=alphabet, min_size=min_size, max_size=max_size)


pdf_like_bytes = st.one_of(
    # Valid tiny PDFs like in other tests
    st.just(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"),
    # Random bytes starting with %PDF
    st.builds(
        lambda tail: b"%PDF-" + tail,
        st.binary(min_size=1, max_size=MAX_PDF_BYTES - 5),
    ),
    # Completely random junk (to exercise error handling)
    st.binary(min_size=1, max_size=MAX_PDF_BYTES),
)


def random_email() -> st.SearchStrategy:
    """Very simple email generator that should still satisfy the server's validation."""
    local = random_ascii(min_size=3, max_size=12)
    domain = random_ascii(min_size=3, max_size=12).map(
        lambda s: "".join(ch for ch in s if ch.isalnum())
    )

    return st.builds(
        lambda l, d: f"{l.strip().replace(' ', '').lower()}@{d or 'example'}.test",
        local,
        domain,
    )


def random_login() -> st.SearchStrategy:
    """Login: letters + digits only (to keep server-side validation happy)."""
    alphabet = string.ascii_letters + string.digits
    return st.text(alphabet=alphabet, min_size=3, max_size=16)


def random_password() -> st.SearchStrategy:
    return random_ascii(min_size=4, max_size=32)


def upload_one_pdf(client, auth_headers, name: str, content: bytes):
    """Helper to upload a single PDF (or PDF-like) and return the response."""
    data = {
        "file": (io.BytesIO(content), name),
        "name": name,
    }
    return client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )


def assume_no_5xx(r):
    """Common property: API should not respond with a 5xx."""
    assert r.status_code < 500, f"Unexpected 5xx: {r.status_code} {r.get_data(as_text=True)}"


# ---------------------------------------------------------------------------
# Fuzz create-user + login
# ---------------------------------------------------------------------------


@given(
    email=random_email(),
    login=random_login(),
    password=random_password(),
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_create_user_and_login(client, email, login, password):
    # Try to create a user; duplicate (409) is fine as long as it's not a 5xx
    r_create = client.post(
        "/api/create-user",
        json={"email": email, "login": login, "password": password},
    )
    assume_no_5xx(r_create)

    # Try to log in with the same credentials (may or may not succeed)
    r_login = client.post(
        "/api/login",
        json={"email": email, "password": password},
    )
    assume_no_5xx(r_login)


# ---------------------------------------------------------------------------
# Fuzz upload-document + list-documents + get-document
# ---------------------------------------------------------------------------


@given(
    pdf_content=pdf_like_bytes,
    filename=random_ascii(min_size=3, max_size=20).map(
        lambda s: "".join(ch for ch in s if ch.isalnum()) + ".pdf"
    ),
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_upload_and_list_get_document(client, auth_headers, pdf_content, filename):
    # Upload
    r_up = upload_one_pdf(client, auth_headers, filename, pdf_content)
    assume_no_5xx(r_up)

    # If upload didn't succeed, we still want to ensure it wasn't a 5xx and then stop.
    if r_up.status_code not in (200, 201):
        return

    doc = r_up.get_json()
    doc_id = doc.get("id")

    # List documents
    r_list = client.get("/api/list-documents", headers=auth_headers)
    assume_no_5xx(r_list)
    if r_list.status_code == 200:
        docs = r_list.get_json().get("documents", [])
        # doc_id, if present, should appear in the list
        if doc_id is not None:
            assert any(d.get("id") == doc_id for d in docs)

    # Get-document via path param
    if doc_id is not None:
        r_get = client.get(f"/api/get-document/{doc_id}", headers=auth_headers)
        assume_no_5xx(r_get)


# ---------------------------------------------------------------------------
# Fuzz watermark creation + reading
# ---------------------------------------------------------------------------


@given(
    pdf_content=pdf_like_bytes,
    secret=random_ascii(min_size=1, max_size=MAX_TEXT_LENGTH),
    key=random_ascii(min_size=1, max_size=MAX_TEXT_LENGTH),
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_create_and_read_watermark(client, auth_headers, pdf_content, secret, key):
    # Upload document first
    r_up = upload_one_pdf(client, auth_headers, "wm_fuzz.pdf", pdf_content)
    assume_no_5xx(r_up)

    if r_up.status_code not in (200, 201):
        return

    doc_id = r_up.get_json().get("id")

    # Fetch available methods
    r_methods = client.get("/api/get-watermarking-methods", headers=auth_headers)
    assume_no_5xx(r_methods)
    if r_methods.status_code != 200:
        return

    methods = r_methods.get_json().get("methods", [])
    if not methods:
        return
    method_name = random.choice(methods)["name"]

    # Create watermark
    r_wm = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=auth_headers,
        json={
            "method": method_name,
            "position": None,
            "key": key,
            "secret": secret,
            "intended_for": "fuzz@example.test",
        },
    )
    assume_no_5xx(r_wm)

    if r_wm.status_code not in (200, 201):
        return

    wm = r_wm.get_json()
    version_id = wm.get("id")

    # List versions for that document
    r_list_versions = client.get(
        f"/api/list-versions/{doc_id}", headers=auth_headers
    )
    assume_no_5xx(r_list_versions)

    if r_list_versions.status_code == 200 and version_id is not None:
        versions = r_list_versions.get_json().get("versions", [])
        assert any(v.get("id") == version_id for v in versions)

    # Try reading the watermark back. It might fail for a number of reasons,
    # but it should not 5xx.
    r_read = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=auth_headers,
        json={
            "method": wm.get("method"),
            "position": wm.get("position"),
            "key": key,
        },
    )
    assume_no_5xx(r_read)


# ---------------------------------------------------------------------------
# Fuzz delete-document and list-all-versions
# ---------------------------------------------------------------------------


@given(
    pdf_content=pdf_like_bytes,
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_delete_document_and_list_all_versions(client, auth_headers, pdf_content):
    # Upload a document
    r_up = upload_one_pdf(client, auth_headers, "todelete.pdf", pdf_content)
    assume_no_5xx(r_up)

    if r_up.status_code not in (200, 201):
        return

    doc_id = r_up.get_json().get("id")

    # List all versions (may be empty)
    r_all = client.get("/api/list-all-versions", headers=auth_headers)
    assume_no_5xx(r_all)
    if r_all.status_code == 200:
        assert isinstance(r_all.get_json().get("versions", []), list)

    # Delete the document
    r_del = client.delete(f"/api/delete-document/{doc_id}", headers=auth_headers)
    assume_no_5xx(r_del)

    # After deletion, various responses are acceptable (404, 403, etc.),
    # but none should be a 5xx.
    r_get = client.get(f"/api/get-document/{doc_id}", headers=auth_headers)
    assume_no_5xx(r_get)


# ---------------------------------------------------------------------------
# Lightweight fuzzing of get-watermarking-methods alone
# ---------------------------------------------------------------------------


@given(
    dummy=st.integers(),  # just to drive multiple examples
)
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_fuzz_get_watermarking_methods(client, auth_headers, dummy):
    r = client.get("/api/get-watermarking-methods", headers=auth_headers)
    assume_no_5xx(r)
    if r.status_code == 200:
        data = r.get_json()
        assert "methods" in data
        assert isinstance(data["methods"], list)
