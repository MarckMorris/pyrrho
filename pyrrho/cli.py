"""Command line interface.

Exit codes are the contract with CI, so they are narrow and stable:

    0  reviewed, nothing at or above the threshold
    1  reviewed, findings at or above the threshold: block the pipeline
    2  could not review (bad plan file, bad arguments, unreadable baseline)

Anything that is not a finding goes to stderr, so ``--format json`` can be piped
without filtering.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from . import __version__, attest, baseline as baseline_mod, core, plan as plan_mod, sarif
from .core import Report, Severity, Verdict

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

_VERDICT_COLOR = {
    Verdict.PASS: "\033[1;32m",
    Verdict.WARN: "\033[1;33m",
    Verdict.BLOCK: "\033[1;31m",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyrrho",
        description=(
            "Adversarial review of a Terraform plan. Reports what the plan actually "
            "does, and what it newly exposes, with the evidence for each claim."
        ),
        epilog=(
            "Generate the input with:\n"
            "  terraform plan -out=tfplan.binary\n"
            "  terraform show -json tfplan.binary > plan.json\n"
            "  pyrrho plan.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("plan", nargs="?", help="path to terraform plan JSON")
    parser.add_argument("--version", action="version", version=f"pyrrho {__version__}")

    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format for the report (default: text)",
    )
    parser.add_argument(
        "--analyzer",
        action="append",
        dest="analyzers",
        metavar="NAME",
        help=(
            "run only this analyzer; repeatable. "
            f"Available: {', '.join(core.available()) or 'none'}"
        ),
    )
    parser.add_argument(
        "--list-analyzers",
        action="store_true",
        help="print the available analyzers and exit",
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        metavar="SEVERITY",
        help="exit 1 when a finding at or above this severity is counted (default: high)",
    )
    parser.add_argument(
        "--claim",
        action="append",
        metavar="PATTERN",
        help=(
            "resource address pattern this change is declared to touch (fnmatch, "
            "repeatable). Anything else in the plan is reported as out of scope."
        ),
    )
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        help="write a SARIF 2.1.0 file for upload to GitHub code scanning",
    )
    parser.add_argument(
        "--sarif-location",
        metavar="PATH",
        help="repository path to anchor SARIF alerts to (default: the plan file)",
    )
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="suppress findings recorded in this baseline file",
    )
    parser.add_argument(
        "--init-baseline",
        metavar="PATH",
        help="write current findings to a baseline file and exit 0",
    )
    parser.add_argument(
        "--attest",
        metavar="PATH",
        help=(
            "write a signed record of what was reviewed. Set PYRRHO_ATTEST_KEY to "
            "sign it; without the key the record is written but marked unsigned."
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colour in text output",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the verdict line",
    )
    return parser


def review(
    plan: plan_mod.Plan,
    analyzer_names: Sequence[str] | None = None,
    claim: Sequence[str] | None = None,
) -> Report:
    """Run the requested analyzers over a plan and collect a report."""
    analyzers = core.resolve(list(analyzer_names) if analyzer_names else None, claim=list(claim or []))
    report = Report(
        plan_path=plan.path,
        plan_digest=plan.digest,
        terraform_version=plan.terraform_version,
        format_version=plan.format_version,
        analyzers=[a.name for a in analyzers],
        resources_examined=len(plan.effective_changes),
    )
    for analyzer in analyzers:
        report.extend(analyzer.run(plan))
    return report


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def render_text(report: Report, threshold: Severity, color: bool, quiet: bool, out: TextIO) -> None:
    verdict = report.verdict(threshold)

    if not quiet:
        print(
            f"{_paint('pyrrho', _BOLD, color)} reviewed "
            f"{report.resources_examined} changing resource(s) in {report.plan_path}",
            file=out,
        )
        if report.terraform_version:
            print(
                _paint(f"  terraform {report.terraform_version}  "
                       f"plan sha256 {report.plan_digest[:12]}  "
                       f"analyzers: {', '.join(sorted(report.analyzers))}", _DIM, color),
                file=out,
            )
        print(file=out)

        if not report.findings:
            print("  No objections. That is not the same as safe: pyrrho only", file=out)
            print("  checks what its analyzers cover.", file=out)
            print(file=out)

        for finding in report.sorted_findings():
            mark = "~" if finding.suppressed else "!"
            label = finding.severity.value.upper().ljust(8)
            head = _paint(f"{mark} {label}", _COLOR[finding.severity], color)
            print(f"{head} {_paint(finding.rule_id, _BOLD, color)}  {finding.title}", file=out)
            print(f"  {_paint('resource', _DIM, color)}  {finding.resource}", file=out)
            for line in _wrap(finding.detail, 74):
                print(f"            {line}", file=out)
            if finding.evidence:
                print(f"  {_paint('evidence', _DIM, color)}", file=out)
                for line in json.dumps(
                    finding.evidence, indent=2, default=str, sort_keys=True
                ).splitlines():
                    print(f"            {_paint(line, _DIM, color)}", file=out)
            if finding.remediation:
                print(f"  {_paint('fix', _DIM, color)}", file=out)
                for line in _wrap(finding.remediation, 74):
                    print(f"            {line}", file=out)
            if finding.suppressed:
                print(f"            {_paint('(suppressed by baseline)', _DIM, color)}", file=out)
            print(file=out)

    counts = report.by_severity()
    tally = "  ".join(
        f"{counts[s.value]} {s.value}" for s in Severity if counts[s.value]
    ) or "no findings"
    suppressed = len(report.suppressed)
    suffix = f"  ({suppressed} suppressed by baseline)" if suppressed else ""

    print(
        f"{_paint(verdict.value.upper(), _VERDICT_COLOR[verdict], color)}  "
        f"{tally}{suffix}  threshold: {threshold.value}",
        file=out,
    )


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _write(path: str, content: str, err: TextIO) -> None:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    print(f"wrote {target}", file=err)


def main(argv: Sequence[str] | None = None, out: TextIO | None = None, err: TextIO | None = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_analyzers:
        for name in core.available():
            analyzer = core.REGISTRY[name]()
            print(f"{name}\n    {analyzer.description}", file=out)
        return EXIT_OK

    if not args.plan:
        parser.print_usage(file=err)
        print("pyrrho: a plan file is required", file=err)
        return EXIT_ERROR

    try:
        threshold = Severity.parse(args.fail_on)
    except ValueError as exc:
        print(f"pyrrho: {exc}", file=err)
        return EXIT_ERROR

    try:
        parsed = plan_mod.load(args.plan)
    except plan_mod.PlanFormatError as exc:
        print(f"pyrrho: {exc}", file=err)
        return EXIT_ERROR

    try:
        report = review(parsed, args.analyzers, args.claim)
    except ValueError as exc:
        print(f"pyrrho: {exc}", file=err)
        return EXIT_ERROR

    if args.init_baseline:
        _write(args.init_baseline, baseline_mod.dumps(report), err)
        print(
            f"pyrrho: baselined {len(report.findings)} finding(s). "
            f"They stay visible in reports and stop affecting the exit code.",
            file=err,
        )
        return EXIT_OK

    if args.baseline:
        try:
            suppressed = baseline_mod.load(args.baseline)
        except baseline_mod.BaselineError as exc:
            print(f"pyrrho: {exc}", file=err)
            return EXIT_ERROR
        report = baseline_mod.apply(report, suppressed)
        for fingerprint in sorted(baseline_mod.stale(report, suppressed)):
            print(
                f"pyrrho: baseline entry {fingerprint} no longer matches anything; "
                f"consider removing it",
                file=err,
            )

    verdict = report.verdict(threshold)

    if args.sarif:
        _write(args.sarif, sarif.dumps(report, location=args.sarif_location), err)

    if args.attest:
        _write(args.attest, attest.dumps(report, threshold, verdict), err)

    if args.format == "json":
        payload: dict[str, Any] = report.to_dict()
        payload["threshold"] = threshold.value
        payload["verdict"] = verdict.value
        print(json.dumps(payload, indent=2, default=str), file=out)
    else:
        color = (not args.no_color) and hasattr(out, "isatty") and out.isatty()
        render_text(report, threshold, color, args.quiet, out)

    return EXIT_BLOCKED if verdict is Verdict.BLOCK else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
