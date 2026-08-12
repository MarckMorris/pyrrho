#!/usr/bin/env python3
"""Review the whole corpus and emit one SARIF file anchored to the corpus HCL.

CI uploads the result to this repository's own Security tab. That is the
demonstration: the alerts are real, they are produced by the tool on every push,
and each one points at the Terraform file in this repository that causes it.
A screenshot of a Security tab is easy to fake; a live one is not.

Run:  python scripts/self_review.py --output pyrrho-corpus.sarif
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pyrrho import cli, plan as plan_mod, sarif  # noqa: E402

CORPUS = ROOT / "corpus"


def merged_sarif() -> dict[str, Any]:
    """One SARIF run whose results point at each case's own main.tf."""
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for case in manifest["cases"]:
        parsed = plan_mod.load(CORPUS / case["plan"])
        report = cli.review(parsed, [case["analyzer"]], case.get("claim") or [])
        if not report.findings:
            continue

        # Anchor to the repository-relative path of the case's Terraform source.
        location = (CORPUS / case["terraform"]).relative_to(ROOT).as_posix()
        doc = sarif.to_sarif(report, location=location)
        run = doc["runs"][0]

        for result in run["results"]:
            source_rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
            rule_id = source_rule["id"]
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append(source_rule)
            result["ruleIndex"] = rule_index[rule_id]
            # Keep alerts from different cases distinct even when the rule and
            # the resource address coincide across cases.
            result["partialFingerprints"] = {
                "pyrrhoFinding/v1": f"{case['id']}:{result['partialFingerprints']['pyrrhoFinding/v1']}"
            }
            result["properties"]["corpusCase"] = case["id"]
            result["properties"]["benignControl"] = case["benign"]
            results.append(result)

    from pyrrho import __version__

    return {
        "$schema": sarif.SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pyrrho",
                        "version": __version__,
                        "informationUri": sarif.INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "pyrrho/corpus"},
                "results": results,
                "properties": {
                    "corpusCases": len(manifest["cases"]),
                    "note": (
                        "Findings produced by pyrrho against its own corpus of deliberately "
                        "dangerous Terraform changes. They are expected: the corpus exists to "
                        "make them happen."
                    ),
                },
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output", default="pyrrho-corpus.sarif", help="path to write")
    args = parser.parse_args(argv)

    doc = merged_sarif()
    Path(args.output).write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    print(f"wrote {args.output}: {len(doc['runs'][0]['results'])} results, "
          f"{len(doc['runs'][0]['tool']['driver']['rules'])} distinct rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
