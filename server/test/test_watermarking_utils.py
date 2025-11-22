import io
import base64
import pytest


from watermarking_utils import (
    METHODS,
    register_method,
    get_method,
    apply_watermark,
    read_watermark,
    is_watermarking_applicable,
    explore_pdf,
)
from watermarking_method import WatermarkingMethod



class DummyMethod(WatermarkingMethod):
    """Simple dummy method for registry tests."""

    name = "dummy-method"

    def add_watermark(self, pdf, secret: str, key: str, position: str | None = None) -> bytes:
        data = pdf if isinstance(pdf, (bytes, bytearray)) else pdf.read()
        return data + f"\nSECRET:{secret}|KEY:{key}".encode("utf-8")

    def read_secret(self, pdf, key: str) -> str:
        data = pdf if isinstance(pdf, (bytes, bytearray)) else pdf.read()
        marker = b"SECRET:"
        idx = data.rfind(marker)
        if idx == -1:
            raise ValueError("no secret marker")
        tail = data[idx + len(marker):].decode("utf-8")
        secret, got_key = tail.split("|KEY:")
        if got_key != key:
            raise ValueError("wrong key")
        return secret

    def is_watermark_applicable(self, pdf, position: str | None = None) -> bool:
        # This dummy method just always says "yes"
        return True


def tiny_pdf_bytes() -> bytes:
    """Very small valid-ish PDF."""
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


def test_get_method_known_and_unknown():
    # toy-eof must be registered by default
    m = get_method("toy-eof")
    assert m is METHODS["toy-eof"]

    with pytest.raises(KeyError):
        get_method("no-such-method")


def test_register_method_overwrites_when_allowed():
    dummy = DummyMethod()
    register_method(dummy, overwrite=True)
    assert METHODS[dummy.name] is dummy

    # Now use apply_watermark via the registry
    pdf = tiny_pdf_bytes()
    wm = apply_watermark("dummy-method", pdf=pdf, secret="s1", key="k1", position=None)
    assert b"SECRET:s1|KEY:k1" in wm

    # And read it back through read_watermark helper
    recovered = read_watermark("dummy-method", pdf=wm, key="k1", position=None)
    assert recovered == "s1"


def test_is_watermarking_applicable_delegates_to_method():
    pdf = tiny_pdf_bytes()
    ok = is_watermarking_applicable("toy-eof", pdf=pdf, position=None)
    # Our AddAfterEOF implementation always returns True
    assert ok is True


def test_apply_watermark_and_read_watermark_roundtrip_toy_eof():
    pdf = tiny_pdf_bytes()
    secret = "utils-secret"
    key = "utils-key"

    wm_pdf = apply_watermark("toy-eof", pdf=pdf, secret=secret, key=key, position=None)
    assert wm_pdf.startswith(b"%PDF")

    recovered = read_watermark("toy-eof", pdf=wm_pdf, key=key, position=None)
    assert recovered == secret


def test_explore_pdf_falls_back_without_pymupdf():
    # For a tiny valid PDF we should at least get a root dict
    pdf = tiny_pdf_bytes()
    tree = explore_pdf(pdf)

    assert isinstance(tree, dict)
    assert tree.get("type") == "root"
    assert isinstance(tree.get("children"), list)


def test_explore_pdf_handles_invalid_pdf_bytes():
    # Pass junk bytes, explore_pdf should still return something JSON-serializable
    junk = b"THIS IS NOT A PDF"
    tree = explore_pdf(junk)

    assert isinstance(tree, dict)
    assert "children" in tree
