"""A signed record of what was reviewed, when, and against which rules.

The gap this fills: a CI log saying "security review passed" is not evidence.
It cannot be checked later, it does not say which version of which rules ran, and
it does not bind the verdict to the specific plan that was approved. An
attestation is a small JSON document that does all three, and carries an HMAC so
that a later reader can tell whether it was edited.

Key handling is deliberately unglamorous. The key comes from the
``PYRRHO_ATTEST_KEY`` environment variable. When it is absent, pyrrho still
writes the record but marks it ``"signed": false`` rather than pretending. An
unsigned attestation is still useful as a reproducibility record; it is just not
evidence against a motivated editor, and it says so about itself.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any

from .core import Report, Severity, Verdict

FORMAT = "pyrrho-attestation/v1"
KEY_ENV = "PYRRHO_ATTEST_KEY"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build(
    report: Report,
    threshold: Severity,
    verdict: Verdict,
    timestamp: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    """Assemble the attestation document, signing it when a key is available."""
    from . import __version__

    payload: dict[str, Any] = {
        "format": FORMAT,
        "tool": {"name": "pyrrho", "version": __version__},
        "reviewed_at": timestamp or _now(),
        "plan": {
            "path": report.plan_path,
            "sha256": report.plan_digest,
            "terraform_version": report.terraform_version,
            "format_version": report.format_version,
        },
        "analyzers": sorted(report.analyzers),
        "threshold": threshold.value,
        "verdict": verdict.value,
        "resources_examined": report.resources_examined,
        "findings": {
            "total": len(report.findings),
            "counted": len(report.counted),
            "suppressed": len(report.suppressed),
            "by_severity": report.by_severity(),
            "fingerprints": sorted(f.fingerprint for f in report.sorted_findings()),
        },
        "report_sha256": hashlib.sha256(report.canonical_json().encode("utf-8")).hexdigest(),
    }

    secret = key if key is not None else os.environ.get(KEY_ENV, "")
    if secret:
        payload["signed"] = True
        payload["signature"] = {
            "algorithm": "HMAC-SHA256",
            "value": hmac.new(secret.encode("utf-8"), _canonical(payload), hashlib.sha256).hexdigest(),
        }
    else:
        payload["signed"] = False
        payload["signature"] = None
        payload["unsigned_reason"] = (
            f"{KEY_ENV} was not set, so this record proves reproducibility but not integrity."
        )

    return payload


def dumps(
    report: Report,
    threshold: Severity,
    verdict: Verdict,
    timestamp: str | None = None,
    key: str | None = None,
) -> str:
    return json.dumps(build(report, threshold, verdict, timestamp, key), indent=2, sort_keys=True)


def verify(document: dict[str, Any], key: str | None = None) -> tuple[bool, str]:
    """Check an attestation's signature. Returns (ok, human-readable reason)."""
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        return False, f"not a pyrrho attestation (expected format {FORMAT})"

    signature = document.get("signature")
    if not document.get("signed") or not isinstance(signature, dict):
        return False, "the record is unsigned, so integrity cannot be checked"

    secret = key if key is not None else os.environ.get(KEY_ENV, "")
    if not secret:
        return False, f"{KEY_ENV} is not set, so the signature cannot be recomputed"

    claimed = str(signature.get("value", ""))
    # Reproduce the exact payload that was signed: every field except the
    # signature itself, which did not exist yet when the HMAC was computed.
    payload = {k: v for k, v in document.items() if k != "signature"}
    expected = hmac.new(
        secret.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()

    if hmac.compare_digest(claimed, expected):
        return True, "signature valid"
    return False, "signature does not match; the record was altered or a different key was used"
