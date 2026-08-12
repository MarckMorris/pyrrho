"""SARIF 2.1.0 output for GitHub code scanning.

GitHub's Security tab ingests SARIF uploaded by
``github/codeql-action/upload-sarif``. Emitting SARIF turns a pyrrho run into
tracked, deduplicated alerts with history and assignees, instead of a log line
that scrolls past in CI output.

pyrrho reviews a plan file rather than source, so every result is anchored to
the plan's path by default. Point ``--sarif-location`` at the Terraform file the
change came from when you want the alert to land on the code instead.
"""

from __future__ import annotations

import json
from typing import Any

from .core import Finding, Report, Severity

SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/MarckMorris/pyrrho"

# SARIF defines error/warning/note/none. GitHub renders the first three visibly.
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub reads the numeric `security-severity` property to render its own
# Critical / High / Medium / Low badges. Values follow the CVSS 3.1 bands.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _version() -> str:
    from . import __version__

    return str(__version__)


def _help_text(finding: Finding) -> str:
    parts = [finding.detail]
    if finding.remediation:
        parts.append(f"**Remediation.** {finding.remediation}")
    if finding.evidence:
        rendered = json.dumps(finding.evidence, indent=2, default=str, sort_keys=True)
        parts.append(f"**Evidence read from the plan.**\n\n```json\n{rendered}\n```")
    return "\n\n".join(parts)


def _rule(finding: Finding) -> dict[str, Any]:
    """Describe a rule once, in the SARIF rule catalogue."""
    text = _help_text(finding)
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.detail},
        "help": {"text": text, "markdown": text},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "tags": ["terraform", "infrastructure", finding.analyzer],
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "problem.severity": (
                "error" if finding.severity.rank >= Severity.HIGH.rank else "warning"
            ),
        },
    }


def _result(finding: Finding, index: int, location: str) -> dict[str, Any]:
    message = f"{finding.resource}: {finding.detail}"
    if finding.remediation:
        message = f"{message} Remediation: {finding.remediation}"

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": index,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"pyrrhoFinding/v1": finding.fingerprint},
        "properties": {
            "analyzer": finding.analyzer,
            "resource": finding.resource,
            "evidence": finding.evidence,
        },
    }

    if finding.suppressed:
        # SARIF-native suppression: the alert stays in the file but GitHub closes
        # it, so a baselined finding does not silently vanish from the record.
        result["suppressions"] = [
            {"kind": "external", "justification": "Suppressed by pyrrho baseline"}
        ]

    return result


def to_sarif(report: Report, location: str | None = None) -> dict[str, Any]:
    """Render a report as a SARIF 2.1.0 document."""
    uri = location or report.plan_path or "terraform-plan.json"

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in report.sorted_findings():
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(_rule(finding))
        results.append(_result(finding, rule_index[finding.rule_id], uri))

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pyrrho",
                        "version": _version(),
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "pyrrho/terraform"},
                "results": results,
                "properties": {
                    "planDigest": report.plan_digest,
                    "terraformVersion": report.terraform_version,
                    "analyzers": sorted(report.analyzers),
                    "resourcesExamined": report.resources_examined,
                },
            }
        ],
    }


def dumps(report: Report, location: str | None = None) -> str:
    """SARIF as a JSON string, ready to write to a file and upload."""
    return json.dumps(to_sarif(report, location=location), indent=2, default=str)
