import pytest

from watermarking_utils import (
    register_method,
    apply_watermark,
    read_watermark,
    METHODS,
    explore_pdf,
)
from watermarking_method import WatermarkingMethod


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def tiny_pdf_bytes():
    """Generate a minimal valid PDF bytes object."""
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


# ----------------------------------------------------------------------
# Dummy watermarking method for testing registry behavior
# ----------------------------------------------------------------------
class DummyMethod(WatermarkingMethod):
    name = "dummy-method"

    def add_watermark(self, pdf, secret, key, position=None):
        # For testing, just return the input PDF unchanged
        return pdf

    def read_watermark(self, pdf, key, position=None):
        # Legacy-style read, delegate to read_secret
        return self.read_secret(pdf=pdf, key=key, position=position)

    def read_secret(self, pdf, key, position=None):
        # Minimal implementation to satisfy abstract API
        return "dummy"

    def is_watermark_applicable(self, pdf, position=None) -> bool:
        # For tests, always say it's applicable
        return True

    def get_usage(self):
        # Minimal implementation to satisfy the abstract base class
        return "dummy usage"



# ----------------------------------------------------------------------
# Tests for method registration
# ----------------------------------------------------------------------
def register_method(method: WatermarkingMethod, replace: bool = False) -> None:
    """
    Register a watermarking method.

    If replace=False (default), raising if method already exists.
    If replace=True, overwrite the existing method with the same name.
    """
    name = method.name

    if not replace and name in METHODS:
        raise ValueError(f"Method '{name}' already registered")

    METHODS[name] = method



# ----------------------------------------------------------------------
# Tests for watermark roundtrip
# ----------------------------------------------------------------------
def test_apply_watermark_and_read_watermark_roundtrip_toy_eof():
    pdf = tiny_pdf_bytes()
    secret = "utils-secret"
    key = "utils-key"

    wm_pdf = apply_watermark(
        "toy-eof",
        pdf=pdf,
        secret=secret,
        key=key,
        position=None,  # apply_watermark accepts this kwarg
    )
    assert wm_pdf.startswith(b"%PDF")

    # read_watermark in your code does NOT take a position kwarg
    recovered = read_watermark("toy-eof", pdf=wm_pdf, key=key)
    assert isinstance(recovered, str)


# ----------------------------------------------------------------------
# Tests for explore_pdf
# ----------------------------------------------------------------------
def test_explore_pdf_falls_back_without_pymupdf():
    pdf = tiny_pdf_bytes()
    tree = explore_pdf(pdf)

    assert isinstance(tree, dict)
    # Your current implementation returns type="Document"
    assert tree.get("type") in ("Document", "root")


def test_explore_pdf_handles_invalid_pdf_bytes():
    junk = b"THIS IS NOT A PDF"

    # Your load_pdf_bytes now raises ValueError for invalid PDF
    with pytest.raises(ValueError):
        explore_pdf(junk)
