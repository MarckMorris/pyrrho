#!/usr/bin/env python3
"""Run pyrrho against the whole corpus and print the numbers the README quotes.

Every figure in this project's README is produced by this script. If a number
appears there and this script does not print it, the number is wrong and should
be deleted.

There is no sampling and no randomness here, so there is no seed to fix: the
corpus is a fixed set of files and the analyzers are deterministic, which means
two runs on the same commit produce byte-identical output. That property is
itself asserted by tests/test_benchmark.py.

What the numbers mean:

  detection      of the rules each dangerous case says must fire, how many did.
                 A case only counts as detected when every expected rule fired.
  false alarms   forbidden rules that fired anyway, plus any finding on a benign
                 control above its allowed severity. This is the number that
                 decides whether anyone keeps the tool switched on.

Run:  python scripts/benchmark.py [--json] [--verbose]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pyrrho import cli, plan as plan_mod  # noqa: E402
from pyrrho.core import Severity  # noqa: E402

CORPUS = ROOT / "corpus"
MANIFEST = CORPUS / "manifest.json"


def load_manifest() -> dict[str, Any]:
    if not MANIFEST.exists():
        raise SystemExit(
            f"{MANIFEST} not found. Generate the corpus first:\n"
            f"  python scripts/generate_corpus.py"
        )
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    """Review one corpus case and score it against its declared expectations."""
    parsed = plan_mod.load(CORPUS / case["plan"])
    report = cli.review(parsed, [case["analyzer"]], case.get("claim") or [])

    fired = sorted({f.rule_id for f in report.findings})
    expected = list(case["expect"])
    forbidden = list(case["forbid"])

    missed = [rule for rule in expected if rule not in fired]
    wrongly_fired = [rule for rule in fired if rule in forbidden]

    # A benign control may allow findings up to a stated severity (a public
    # HTTPS rule is worth a note, not an alert). Anything above that is a false
    # alarm even if no forbidden rule fired.
    over_severity: list[str] = []
    if case["benign"]:
        ceiling = Severity.parse(case["max_severity"]) if case.get("max_severity") else None
        for finding in report.findings:
            if ceiling is None or finding.severity.rank > ceiling.rank:
                over_severity.append(f"{finding.rule_id}:{finding.severity.value}")

    detected = not missed
    clean = not wrongly_fired and not over_severity

    return {
        "id": case["id"],
        "title": case["title"],
        "analyzer": case["analyzer"],
        "benign": case["benign"],
        "expected": expected,
        "fired": fired,
        "missed": missed,
        "wrongly_fired": wrongly_fired,
        "over_severity": over_severity,
        "detected": detected,
        "clean": clean,
        "findings": len(report.findings),
        "worst": report.worst.value if report.worst else None,
    }


def summarize(results: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
    dangerous = [r for r in results if not r["benign"]]
    controls = [r for r in results if r["benign"]]

    detected = [r for r in dangerous if r["detected"]]
    noisy = [r for r in results if not r["clean"]]

    verified = sum(1 for c in manifest["cases"] if c.get("verified_against_terraform"))

    return {
        "corpus": {
            "dangerous_cases": len(dangerous),
            "benign_controls": len(controls),
            "cases_verified_against_real_terraform": verified,
        },
        "detection": {
            "cases_fully_detected": len(detected),
            "cases_with_a_missed_rule": len(dangerous) - len(detected),
            "rate": round(len(detected) / len(dangerous), 4) if dangerous else 0.0,
        },
        "false_alarms": {
            "cases_with_a_false_alarm": len(noisy),
            "rate_over_all_cases": round(len(noisy) / len(results), 4) if results else 0.0,
        },
        "misses": [
            {"id": r["id"], "missed": r["missed"]} for r in dangerous if r["missed"]
        ],
        "false_alarm_detail": [
            {
                "id": r["id"],
                "wrongly_fired": r["wrongly_fired"],
                "over_severity": r["over_severity"],
            }
            for r in noisy
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    parser.add_argument("--verbose", action="store_true", help="print one line per case")
    args = parser.parse_args(argv)

    manifest = load_manifest()
    results = [run_case(case) for case in manifest["cases"]]
    summary = summarize(results, manifest)

    if args.json:
        print(json.dumps({"summary": summary, "cases": results}, indent=2))
        return 0 if not summary["misses"] and not summary["false_alarm_detail"] else 1

    corpus = summary["corpus"]
    print("pyrrho benchmark")
    print(f"  corpus: {corpus['dangerous_cases']} dangerous cases, "
          f"{corpus['benign_controls']} benign controls")
    print(f"  cases captured from a real terraform plan: "
          f"{corpus['cases_verified_against_real_terraform']}/{len(results)}")
    print()

    if args.verbose:
        for r in results:
            if r["benign"]:
                mark = "ok  " if r["clean"] else "NOISY"
            else:
                mark = "ok  " if r["detected"] and r["clean"] else "FAIL"
            print(f"  {mark}  {r['id']}")
            print(f"        expected {r['expected'] or '(nothing)'}  fired {r['fired'] or '(nothing)'}")
        print()

    det = summary["detection"]
    fa = summary["false_alarms"]
    print(f"  detection    {det['cases_fully_detected']}/{corpus['dangerous_cases']} "
          f"dangerous cases fully detected ({det['rate']:.0%})")
    print(f"  false alarms {fa['cases_with_a_false_alarm']}/{len(results)} cases "
          f"({fa['rate_over_all_cases']:.0%})")

    if summary["misses"]:
        print("\n  missed:")
        for miss in summary["misses"]:
            print(f"    {miss['id']}: {', '.join(miss['missed'])}")

    if summary["false_alarm_detail"]:
        print("\n  false alarms:")
        for fa_case in summary["false_alarm_detail"]:
            bits = fa_case["wrongly_fired"] + fa_case["over_severity"]
            print(f"    {fa_case['id']}: {', '.join(bits)}")

    print()
    print("  Reproduce: python scripts/generate_corpus.py && python scripts/benchmark.py")
    return 0 if not summary["misses"] and not summary["false_alarm_detail"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
