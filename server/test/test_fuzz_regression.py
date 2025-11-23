"""
Regression tests for fuzzing failures.

This module does *not* generate tests itself; instead, it loads JSON files
from `fuzzing/findings/` created by the fuzzing layer (see
`fuzzing/regression_helpers.py`) and replays them as normal API calls.

Workflow:
    1. Run the fuzz tests (test_fuzz_api.py) against a buggy version.
       Any unexpected 5xx responses will create JSON files under
       fuzzing/findings/.
    2. Fix the bug in the application.
    3. Re-run the full test suite. This module will automatically
       replay all recorded failures and ensure they no longer produce 5xx.
"""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

FINDINGS_DIR = Path(__file__).resolve().parent.parent / "fuzzing" / "findings"


def _load_cases() -> List[Dict[str, Any]]:
    if not FINDINGS_DIR.is_dir():
        return []
    cases: List[Dict[str, Any]] = []
    for path in sorted(FINDINGS_DIR.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            data["_source_file"] = str(path)
            cases.append(data)
        except Exception:
            # Malformed JSON shouldn't break the whole test run
            continue
    return cases


CASES = _load_cases()


@pytest.mark.skipif(
    not CASES,
    reason="No fuzzing regression cases recorded yet (fuzzing/findings is empty)",
)
@pytest.mark.parametrize("case", CASES, ids=lambda c: c.get("name", "<unnamed>"))
def test_fuzz_regressions(client, auth_headers, case: Dict[str, Any]):
    """
    Generic replay of fuzzing failures.

    We support two broad shapes:
        - JSON requests (request['json'] present)
        - Upload-style requests (request['bytes_b64'] present)
    """
    method = case["method"].upper()
    path = case["path"]
    request = case.get("request", {})
    status_code = int(case.get("status_code", 500))

    # Build common arguments
    kwargs: Dict[str, Any] = {}
    kwargs["headers"] = auth_headers

    if "json" in request:
        kwargs["json"] = request["json"]

    # Special handling for upload-style cases that stored base64 bytes
    if "bytes_b64" in request and "filename" in request:
        raw_bytes = base64.b64decode(request["bytes_b64"].encode("ascii"))
        pdf_io = io.BytesIO(raw_bytes)
        filename = request["filename"]
        kwargs["data"] = {"file": (pdf_io, filename), "name": filename}
        kwargs["content_type"] = "multipart/form-data"

    # Dispatch to the correct FlaskClient method
    client_method = {
        "GET": client.get,
        "POST": client.post,
        "DELETE": client.delete,
        "PUT": client.put,
        "PATCH": client.patch,
    }.get(method)

    assert client_method is not None, f"Unsupported HTTP method in case: {method}"

    response = client_method(path, **kwargs)

    # The *regression* requirement is: no more 5xx.
    assert response.status_code < 500, (
        f"Regression case from {case.get('_source_file')} still produces 5xx "
        f"({response.status_code})"
    )

    # Optionally tighten the assertion: if the original 5xx was a specific
    # status (e.g. 500), we can also assert the new status is different.
    assert response.status_code != status_code, (
        f"Expected fixed behaviour for regression case {case.get('_source_file')}, "
        f"but got the same HTTP status {response.status_code}"
    )
