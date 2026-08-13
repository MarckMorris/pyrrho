"""Baseline support, so an existing estate can adopt pyrrho without a wall of red.

The failure mode this avoids: a team runs a new scanner against real
infrastructure, gets 200 findings, and turns the scanner off. A baseline records
what was already true on day one so that CI blocks on *new* problems only, while
keeping the accepted ones visible rather than deleted.

Findings are matched by fingerprint (rule + resource address), not by message
text, so rewording a finding does not silently un-suppress it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import Report

FORMAT = "pyrrho-baseline/v1"


class BaselineError(ValueError):
    """The baseline file exists but cannot be used."""


def build(report: Report, note: str = "") -> dict[str, Any]:
    """Turn a report into a baseline document.

    Every entry keeps the human-readable context alongside the fingerprint. A
    baseline whose entries are opaque hashes is a file nobody can review, which
    defeats the point of writing the exceptions down.
    """
    return {
        "format": FORMAT,
        "note": note or "Findings accepted when pyrrho was adopted.",
        "plan_digest": report.plan_digest,
        "entries": [
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "resource": f.resource,
                "aspect": f.key,
                "severity": f.severity.value,
                "title": f.title,
            }
            for f in report.sorted_findings()
        ],
    }


def dumps(report: Report, note: str = "") -> str:
    return json.dumps(build(report, note=note), indent=2, sort_keys=True)


def load(path: str | Path) -> set[str]:
    """Read a baseline file and return the set of suppressed fingerprints."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise BaselineError(
            f"baseline file not found: {p}. Create one with --init-baseline."
        ) from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline file {p} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise BaselineError(
            f"{p} is not a pyrrho baseline (expected \"format\": \"{FORMAT}\")"
        )

    entries = data.get("entries")
    if not isinstance(entries, list):
        raise BaselineError(f"{p} has no 'entries' list")

    out: set[str] = set()
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str):
            out.add(entry["fingerprint"])
    return out


def apply(report: Report, suppressed: set[str]) -> Report:
    """Return a copy of the report with baselined findings marked suppressed.

    Suppressed findings stay in the report and in the SARIF file. They stop
    counting toward the verdict, and that is the only thing that changes.
    """
    import dataclasses

    report.findings = [
        dataclasses.replace(f, suppressed=True) if f.fingerprint in suppressed else f
        for f in report.findings
    ]
    return report


def stale(report: Report, suppressed: set[str]) -> set[str]:
    """Baseline entries that no longer match anything in the current report.

    A baseline that only grows becomes a list of problems that were fixed years
    ago. Reporting the stale entries lets a team prune it.
    """
    present = {f.fingerprint for f in report.findings}
    return suppressed - present
