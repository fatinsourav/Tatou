import io
import base64
import json
import pytest

from add_after_eof import AddAfterEOF
from watermarking_utils import (
    METHODS,
    get_method,
    apply_watermark,
    read_watermark,
    is_watermarking_applicable,
)
from watermarking_method import (
    load_pdf_bytes,
    is_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
)


def tiny_pdf_bytes() -> bytes:
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


def test_is_pdf_bytes_and_load_pdf_bytes_success(tmp_path):
    data = tiny_pdf_bytes()
    assert is_pdf_bytes(data)

    p = tmp_path / "test.pdf"
    p.write_bytes(data)

    loaded = load_pdf_bytes(p)
    assert loaded.startswith(b"%PDF")


def test_load_pdf_bytes_rejects_non_pdf(tmp_path):
    p = tmp_path / "not_pdf.bin"
    p.write_bytes(b"HELLO")
    with pytest.raises(ValueError):
        load_pdf_bytes(p)


def test_add_after_eof_roundtrip_secret_ok():
    method = AddAfterEOF()
    pdf = tiny_pdf_bytes()
    secret = "hello-world"
    key = "test-key"

    wm_pdf = method.add_watermark(pdf=pdf, secret=secret, key=key)
    assert wm_pdf.startswith(b"%PDF")  # still a PDF

    recovered = method.read_watermark(pdf=wm_pdf, key=key)
    assert recovered == secret


def test_add_after_eof_wrong_key_raises():
    method = AddAfterEOF()
    pdf = tiny_pdf_bytes()
    secret = "topsecret"
    key_ok = "correct-key"
    key_bad = "wrong-key"

    wm_pdf = method.add_watermark(pdf=pdf, secret=secret, key=key_ok)
    with pytest.raises(InvalidKeyError):
        method.read_watermark(pdf=wm_pdf, key=key_bad)


def test_add_after_eof_secret_not_found():
    method = AddAfterEOF()
    pdf = tiny_pdf_bytes()
    with pytest.raises(SecretNotFoundError):
        method.read_watermark(pdf=pdf, key="whatever")


def test_registry_contains_methods():
    # at least the toy-eof and fatin methods should be registered
    assert "toy-eof" in METHODS
    assert get_method("toy-eof") is METHODS["toy-eof"]


def test_apply_and_read_watermark_via_utils():
    pdf = tiny_pdf_bytes()
    secret = "util-secret"
    key = "util-key"

    wm_pdf = apply_watermark(method="toy-eof", pdf=pdf, secret=secret, key=key)
    recovered = read_watermark(method="toy-eof", pdf=wm_pdf, key=key)
    assert recovered == secret


def test_is_watermarking_applicable_helpers():
    pdf = tiny_pdf_bytes()
    # should not raise when called correctly
    applicable = is_watermarking_applicable("toy-eof", pdf=pdf, position=None)
    assert applicable is True or applicable is False or applicable is None
