"""
Helpers for recording fuzzing failures and turning them into regression tests.

When a fuzz test detects an unexpected 5xx, it should call `record_failure(...)`.
This writes a small JSON file under `fuzzing/findings/` with enough information
to replay the request.

A generic test module `test/test_fuzz_regressions.py` will then pick up all
JSON files in that directory and replay them as normal pytest tests.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

FINDINGS_DIR = Path(__file__).resolve().parent / "findings"
FINDINGS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class RegressionCase:
    name: str
    method: str
    path: str
    status_code: int
    request: Dict[str, Any]
    response_body: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


def record_failure(
    base_case: Dict[str, Any],
    status_code: int,
    response_body: Optional[str] = None,
) -> Path:
    """
    Persist a fuzzing failure as a JSON file.

    Parameters
    ----------
    base_case:
        Dictionary describing the request that triggered the failure.
        It *must* contain at least:
            - "name": short identifier for the fuzz test
            - "method": HTTP method (GET/POST/DELETE/...)
            - "path": path string (e.g. "/api/upload-document" or
                      "/api/get-document/<id>" – both are fine)
        It may also contain arbitrary additional keys such as "json",
        "filename", "bytes_b64", etc. They will be stored under the
        "request" field.
    status_code:
        Actual HTTP status code observed (typically 5xx).
    response_body:
        Optional textual body of the response, for debugging.

    Returns
    -------
    Path
        The path of the JSON file written under fuzzing/findings/.
    """
    required_keys = {"name", "method", "path"}
    missing = required_keys - base_case.keys()
    if missing:
        raise ValueError(f"record_failure: base_case is missing keys: {missing}")

    case = RegressionCase(
        name=str(base_case["name"]),
        method=str(base_case["method"]),
        path=str(base_case["path"]),
        status_code=int(status_code),
        request={
            k: v for k, v in base_case.items()
            if k not in ("name", "method", "path")
        },
        response_body=response_body,
    )

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    unique = uuid.uuid4().hex[:8]
    filename = f"{case.name}_{timestamp}_{unique}.json"
    out_path = FINDINGS_DIR / filename

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(case.to_json(), f, indent=2, sort_keys=True)

    return out_path
