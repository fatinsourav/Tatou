import os
import sys
import io
import pytest

# -------------------------------------------------------
# Ensure the src/ directory is on sys.path
# -------------------------------------------------------
# test/ directory = /home/lab/Tatou/server/test
# src/ directory  = /home/lab/Tatou/server/src
CURRENT_DIR = os.path.dirname(__file__)
SRC_DIR = os.path.join(os.path.dirname(CURRENT_DIR), "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Now these imports will succeed:
from fatinWM import FatinWM
from watermarking_method import SecretNotFoundError, InvalidKeyError


def test_is_watermark_applicable_accepts_pdf_path_and_bytes(tiny_valid_pdf_file, tiny_valid_pdf_bytes):
    wm = FatinWM()
    # Path ending with .pdf -> True
    assert wm.is_watermark_applicable(str(tiny_valid_pdf_file))
    # Bytes are assumed to be PDFs -> True
    assert wm.is_watermark_applicable(tiny_valid_pdf_bytes)


def test_add_and_read_roundtrip_bytes(tiny_valid_pdf_bytes):
    wm = FatinWM()
    secret = "top_secret_value"
    key = "super_key"

    watermarked = wm.add_watermark(tiny_valid_pdf_bytes, secret=secret, key=key)
    assert isinstance(watermarked, (bytes, bytearray))
    # Marker should be present in output
    assert b"%%FATINWM:" in watermarked

    # Read back
    recovered = wm.read_secret(watermarked, key=key)
    assert recovered == secret


def test_add_and_read_roundtrip_file_path(tiny_valid_pdf_file):
    wm = FatinWM()
    secret = "file_path_secret"
    key = "another_key"

    watermarked = wm.add_watermark(str(tiny_valid_pdf_file), secret=secret, key=key)
    # Save result to another file and read again using path API
    out_path = tiny_valid_pdf_file.parent / "wm.pdf"
    out_path.write_bytes(watermarked)

    recovered = wm.read_secret(str(out_path), key=key)
    assert recovered == secret


def test_add_and_read_roundtrip_fileobj(tiny_valid_pdf_fileobj):
    wm = FatinWM()
    secret = "io_bytes_secret"
    key = "key123"

    watermarked = wm.add_watermark(tiny_valid_pdf_fileobj, secret=secret, key=key)
    recovered = wm.read_secret(watermarked, key=key)
    assert recovered == secret


def test_read_with_wrong_key_raises_invalid_key(tiny_valid_pdf_bytes):
    wm = FatinWM()
    secret = "some_secret"
    key = "correct_key"

    watermarked = wm.add_watermark(tiny_valid_pdf_bytes, secret=secret, key=key)

    with pytest.raises(InvalidKeyError):
        wm.read_secret(watermarked, key="wrong_key")


def test_read_without_watermark_raises_secret_not_found(tiny_valid_pdf_bytes):
    wm = FatinWM()
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(tiny_valid_pdf_bytes, key="any_key")


def test_second_add_replaces_previous_marker(tiny_valid_pdf_bytes):
    wm = FatinWM()
    first = wm.add_watermark(tiny_valid_pdf_bytes, secret="first", key="k")
    second = wm.add_watermark(first, secret="second", key="k")

    # Only one marker should exist
    assert second.count(b"%%FATINWM:") == 1

    recovered = wm.read_secret(second, key="k")
    assert recovered == "second"
