#!/usr/bin/env python3
"""Run Checkov over the same corpus, scored the same way.

pyrrho detecting 100% of a corpus its own author wrote proves very little. The
number that means something is what a mature, widely deployed tool does on the
same input. This script produces it.

**Methodology, stated so the result can be argued with.**

* Checkov and pyrrho are not trying to do the same thing. Checkov evaluates the
  planned end state against a large catalogue of policies. pyrrho compares the
  planned state to the prior state and reports the difference. This script
  measures one specific property — *does the tool tell you this change is
  dangerous, and does it stay quiet when it is not* — and nothing else.
* Rule identifiers do not map between the tools, so a dangerous case counts as
  **detected** when Checkov reports any failed check on it. That is deliberately
  generous to Checkov on recall: it gets credit for flagging the right file even
  for the wrong reason.
* The same rule makes the false-alarm side strict for both tools: any failed
  check on a benign control counts against it.
* `CKV2_AWS_5` ("security groups are attached to another resource") is excluded.
  It fires because each corpus case is a single isolated resource, which is an
  artefact of the corpus, not a finding about the change. Excluding it makes the
  comparison fairer to Checkov.

Run:  python scripts/compare_checkov.py [--json] [--jobs N]
Needs: pip install checkov
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pyrrho import cli, plan as plan_mod  # noqa: E402
from pyrrho.core import Severity  # noqa: E402

CORPUS = ROOT / "corpus"

# Artefacts of one-resource-per-case fixtures rather than judgements about the
# change under review.
EXCLUDED_CHECKS = {"CKV2_AWS_5"}


def checkov_version() -> str | None:
    if not shutil.which("checkov"):
        return None
    result = subprocess.run(["checkov", "--version"], capture_output=True, text=True)
    return result.stdout.strip() or None


def run_checkov(plan_path: Path) -> dict[str, Any]:
    """Failed checks Checkov reports for one plan, or an error marker."""
    result = subprocess.run(
        ["checkov", "-f", str(plan_path), "--skip-download", "-o", "json"],
        capture_output=True,
        text=True,
    )
    raw = result.stdout.strip()
    if not raw:
        return {"error": (result.stderr.strip().splitlines() or ["no output"])[-1]}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"error": f"unparseable output: {exc}"}

    reports = parsed if isinstance(parsed, list) else [parsed]
    failed: list[str] = []
    resources = 0
    for report in reports:
        summary = report.get("summary", {}) or {}
        resources = max(resources, int(summary.get("resource_count") or 0))
        for check in (report.get("results", {}) or {}).get("failed_checks", []) or []:
            check_id = check.get("check_id")
            if check_id and check_id not in EXCLUDED_CHECKS:
                failed.append(check_id)
    return {"failed": sorted(set(failed)), "resources": resources}


def run_pyrrho(case: dict[str, Any]) -> dict[str, Any]:
    plan = plan_mod.load(CORPUS / case["plan"])
    # No --claim: RD007 needs a declared scope that Checkov has no equivalent
    # for, so giving pyrrho one would not be a like-for-like comparison.
    report = cli.review(plan, None, [])
    return {
        "findings": sorted({f.rule_id for f in report.findings}),
        "worst": report.worst.value if report.worst else None,
    }


def score(case: dict[str, Any], reported: list[str]) -> dict[str, bool]:
    """One case, one tool. Detected when dangerous, quiet when benign."""
    if case["benign"]:
        return {"detected": True, "quiet": not reported}
    return {"detected": bool(reported), "quiet": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--jobs", type=int, default=6, help="parallel Checkov runs")
    args = parser.parse_args(argv)

    version = checkov_version()
    if version is None:
        print("checkov is not installed. pip install checkov", file=sys.stderr)
        return 2

    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    cases = manifest["cases"]

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        checkov_results = list(
            pool.map(lambda c: run_checkov(CORPUS / c["plan"]), cases)
        )

    rows: list[dict[str, Any]] = []
    for case, ck in zip(cases, checkov_results):
        py = run_pyrrho(case)
        ck_failed = ck.get("failed", [])
        rows.append(
            {
                "id": case["id"],
                "benign": case["benign"],
                "pyrrho": py["findings"],
                "pyrrho_worst": py["worst"],
                "pyrrho_score": score(case, py["findings"]),
                "checkov": ck_failed,
                "checkov_error": ck.get("error"),
                "checkov_resources": ck.get("resources", 0),
                "checkov_score": score(case, ck_failed),
            }
        )

    dangerous = [r for r in rows if not r["benign"]]
    controls = [r for r in rows if r["benign"]]

    def tally(key: str) -> dict[str, Any]:
        detected = sum(1 for r in dangerous if r[key]["detected"])
        noisy = sum(1 for r in controls if not r[key]["quiet"])
        return {
            "detected": detected,
            "of": len(dangerous),
            "detection_rate": round(detected / len(dangerous), 4) if dangerous else 0.0,
            "false_alarms": noisy,
            "controls": len(controls),
        }

    summary = {
        "checkov_version": version,
        "excluded_checks": sorted(EXCLUDED_CHECKS),
        "pyrrho": tally("pyrrho_score"),
        "checkov": tally("checkov_score"),
        "checkov_errors": [r["id"] for r in rows if r["checkov_error"]],
    }

    if args.json:
        print(json.dumps({"summary": summary, "cases": rows}, indent=2))
        return 0

    print(f"pyrrho vs. Checkov {version}, same corpus, same scoring")
    print(f"  a dangerous case counts as detected when the tool reports anything on it")
    print(f"  excluded as a corpus artefact: {', '.join(sorted(EXCLUDED_CHECKS))}")
    print()
    header = f"  {'case':52s} {'pyrrho':22s} checkov"
    print(header)
    print(f"  {'-' * (len(header) - 2)}")
    for row in rows:
        mark = "benign " if row["benign"] else "DANGER "
        severity = f"[{row['pyrrho_worst']}]" if row["pyrrho_worst"] else ""
        py = (",".join(row["pyrrho"]) + " " + severity).strip() or "-"
        ck = ",".join(row["checkov"]) or (row["checkov_error"] or "-")
        print(f"  {mark}{row['id'][:44]:45s} {py[:27]:28s} {ck[:38]}")

    print()
    for name in ("pyrrho", "checkov"):
        t = summary[name]
        print(
            f"  {name:8s} detected {t['detected']}/{t['of']} dangerous "
            f"({t['detection_rate']:.0%})   false alarms "
            f"{t['false_alarms']}/{t['controls']} controls"
        )
    if summary["checkov_errors"]:
        print(f"\n  checkov errored on: {', '.join(summary['checkov_errors'])}")

    print()
    print("  Read this fairly:")
    print(
        f"   * Checkov is not trying to do delta analysis. Its "
        f"{summary['checkov']['false_alarms']} false alarm(s) are failures against pyrrho's"
    )
    print("     definition of the job, not against its own. On its own terms it is right.")
    noisy_pyrrho = [r["id"] for r in controls if not r["pyrrho_score"]["quiet"]]
    if noisy_pyrrho:
        print(
            f"   * pyrrho's own false alarm(s): {', '.join(noisy_pyrrho)}. Scored strictly,"
        )
        print("     with no exemption that Checkov does not also get.")
    missed_pyrrho = [r["id"] for r in dangerous if not r["pyrrho_score"]["detected"]]
    if missed_pyrrho:
        print(f"   * pyrrho misses: {', '.join(missed_pyrrho)}.")
        print("     rd007 needs --claim, which has no Checkov equivalent, so it is withheld.")
    print()
    print("  Reproduce: pip install checkov && python scripts/compare_checkov.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
