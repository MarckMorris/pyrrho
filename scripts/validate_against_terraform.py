#!/usr/bin/env python3
"""Validate the parser against plan JSON that Terraform itself produced.

The corpus in this repository is written to Terraform's documented plan format
rather than captured from a live run, and the README says so. This script closes
the more important half of that gap without needing a Terraform binary, cloud
credentials, or a network path to the provider registry.

HashiCorp's own repository contains the golden files it uses to test
`terraform show -json`. They were produced by Terraform, they cover the format's
awkward corners on purpose, and they span several format versions. Parsing all
of them is a real answer to "does this handle what Terraform actually emits?"

**These files are not vendored into this repository, deliberately.**
hashicorp/terraform is licensed BUSL-1.1, which this MIT project cannot
redistribute. The script fetches them at a pinned commit, reads them in place,
and reports. Nothing is copied into the tree.

Run:  python scripts/validate_against_terraform.py [--json] [--keep]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pyrrho import cli, plan as plan_mod  # noqa: E402

TERRAFORM_REPO = "https://github.com/hashicorp/terraform.git"

# Pinned so the result is reproducible. Bump deliberately, and re-read the
# output: a new golden file is exactly the kind of thing this script exists to
# notice.
TERRAFORM_COMMIT = "7d231820db94dcfb86b3a95482130e54e5404479"

# Only the directories that hold plan JSON, so the checkout stays small.
SPARSE_PATHS = ["/internal/command/**", "/internal/cloud/testdata/**"]


class FetchError(RuntimeError):
    pass


def fetch(dest: Path) -> None:
    """Blobless, sparse checkout of the pinned commit."""

    def git(*args: str, cwd: Path | None = None) -> None:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True
        )
        if result.returncode != 0:
            raise FetchError(f"git {' '.join(args)} failed:\n{result.stderr.strip()}")

    dest.mkdir(parents=True, exist_ok=True)
    git("init", "-q", str(dest))
    git("remote", "add", "origin", TERRAFORM_REPO, cwd=dest)
    git("config", "extensions.partialClone", "origin", cwd=dest)
    git("sparse-checkout", "init", "--no-cone", cwd=dest)
    git("sparse-checkout", "set", "--no-cone", *SPARSE_PATHS, cwd=dest)
    git(
        "fetch", "--depth", "1", "--filter=blob:none", "origin", TERRAFORM_COMMIT,
        cwd=dest,
    )
    git("checkout", "-q", "FETCH_HEAD", cwd=dest)


def plan_files(root: Path) -> list[Path]:
    """Every JSON in the checkout that is actually a plan."""
    found = []
    for path in sorted(root.rglob("*.json")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if '"resource_changes"' in text:
            found.append(path)
    return found


def examine(root: Path) -> dict[str, Any]:
    files = plan_files(root)
    if not files:
        raise FetchError(
            "no plan JSON found in the checkout; the upstream layout may have moved"
        )

    parsed: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    formats: set[str] = set()
    versions: set[str] = set()
    flavours: set[str] = set()
    action_sets: set[str] = set()
    action_reasons: set[str] = set()
    findings_by_file: dict[str, list[str]] = {}
    crashes: list[dict[str, str]] = []

    for path in files:
        name = str(path.relative_to(root))
        try:
            plan = plan_mod.load(path)
        except plan_mod.PlanFormatError as exc:
            failures.append({"file": name, "error": str(exc)})
            continue

        formats.add(plan.format_version)
        flavours.add(plan.flavour)
        if plan.terraform_version:
            versions.add(plan.terraform_version)
        for rc in plan.resource_changes:
            action_sets.add("+".join(rc.actions))
            if rc.action_reason:
                action_reasons.add(rc.action_reason)

        parsed.append({"file": name, "changes": len(plan.effective_changes)})

        # Parsing is only half of it. The analyzers must also survive real input.
        try:
            report = cli.review(plan, None, [])
        except Exception:  # noqa: BLE001 - the point is to catch anything
            crashes.append({"file": name, "traceback": traceback.format_exc(limit=3)})
            continue
        if report.findings:
            findings_by_file[name] = sorted({f.rule_id for f in report.findings})

    return {
        "commit": TERRAFORM_COMMIT,
        "files_found": len(files),
        "parsed": len(parsed),
        "rejected": len(failures),
        "analyzer_crashes": len(crashes),
        "format_versions": sorted(formats),
        "terraform_versions": sorted(versions),
        "plan_flavours": sorted(flavours),
        "action_sets": sorted(action_sets),
        "action_reasons": sorted(action_reasons),
        "findings": findings_by_file,
        "rejections": failures,
        "crashes": crashes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--keep", action="store_true", help="keep the checkout")
    parser.add_argument("--checkout", help="use an existing checkout instead of fetching")
    args = parser.parse_args(argv)

    if args.checkout:
        root = Path(args.checkout)
        temp = None
    else:
        temp = Path(tempfile.mkdtemp(prefix="pyrrho-tf-"))
        root = temp
        try:
            fetch(root)
        except FetchError as exc:
            print(f"could not fetch hashicorp/terraform: {exc}", file=sys.stderr)
            print(
                "This script needs network access to github.com. Skipping it does not "
                "affect the test suite; it affects only this validation.",
                file=sys.stderr,
            )
            shutil.rmtree(temp, ignore_errors=True)
            return 2

    try:
        result = examine(root)
    finally:
        if temp is not None and not args.keep:
            shutil.rmtree(temp, ignore_errors=True)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("pyrrho parser vs. Terraform's own plan JSON golden files")
        print(f"  source: hashicorp/terraform @ {result['commit'][:12]} (BUSL-1.1, not vendored)")
        print()
        print(f"  plan documents found  {result['files_found']}")
        print(f"  parsed                {result['parsed']}")
        print(f"  rejected              {result['rejected']}")
        print(f"  analyzer crashes      {result['analyzer_crashes']}")
        print()
        print(f"  plan format versions  {', '.join(result['format_versions'])}")
        print(f"  terraform versions    {', '.join(result['terraform_versions'])}")
        print(f"  plan flavours         {', '.join(result['plan_flavours'])}")
        print(f"  action sets           {', '.join(result['action_sets'])}")
        print(f"  action reasons        {', '.join(result['action_reasons'])}")
        if result["findings"]:
            print()
            print("  findings on real plans:")
            for name, rules in sorted(result["findings"].items()):
                print(f"    {', '.join(rules):10s} {name}")
        for rejection in result["rejections"]:
            print(f"\n  REJECTED {rejection['file']}\n    {rejection['error']}")
        for crash in result["crashes"]:
            print(f"\n  CRASH {crash['file']}\n{crash['traceback']}")

    # A rejection or a crash is a real failure: these are documents Terraform
    # produced, so anything we cannot read is a gap in the parser.
    return 1 if (result["rejected"] or result["analyzer_crashes"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
