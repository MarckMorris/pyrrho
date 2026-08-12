"""The corpus is the specification, so it is asserted like one.

These tests fail if a case is added without expectations, if a plan file stops
parsing, if a rule stops firing on the case that documents it, or if the
benchmark stops being deterministic.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from pyrrho import cli, plan as plan_mod
from pyrrho.core import REGISTRY, Severity

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
MANIFEST = CORPUS / "manifest.json"


def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


CASES = manifest()["cases"]
IDS = [c["id"] for c in CASES]


class TestManifestIntegrity:
    def test_the_manifest_exists_and_is_current(self):
        assert MANIFEST.exists(), "run scripts/generate_corpus.py"

    def test_every_case_has_both_files(self):
        for case in CASES:
            assert (CORPUS / case["plan"]).exists(), case["id"]
            assert (CORPUS / case["terraform"]).exists(), case["id"]

    def test_case_ids_are_unique(self):
        assert len(IDS) == len(set(IDS))

    def test_every_case_names_a_real_analyzer(self):
        for case in CASES:
            assert case["analyzer"] in REGISTRY, case["id"]

    def test_dangerous_cases_expect_something(self):
        for case in CASES:
            if not case["benign"]:
                assert case["expect"], f"{case['id']} expects no rule; it is not a dangerous case"

    def test_benign_controls_expect_nothing(self):
        for case in CASES:
            if case["benign"]:
                assert case["expect"] == [], case["id"]

    def test_every_case_explains_why_it_is_realistic(self):
        for case in CASES:
            assert len(case["why"]) > 40, case["id"]

    def test_the_corpus_has_enough_of_both_kinds(self):
        counts = manifest()["counts"]
        assert counts["dangerous"] >= 20
        assert counts["benign_controls"] >= 4

    def test_the_counts_match_the_cases(self):
        counts = manifest()["counts"]
        assert counts["total"] == len(CASES)
        assert counts["dangerous"] == sum(1 for c in CASES if not c["benign"])
        assert counts["benign_controls"] == sum(1 for c in CASES if c["benign"])

    def test_no_case_claims_to_be_captured_from_real_terraform_yet(self):
        """Guards the honesty claim in the README.

        If someone regenerates the corpus from a real terraform binary they must
        flip this flag, and this test is where they will notice they also need to
        update the README sentence that says none of them are.
        """
        for case in CASES:
            assert case["verified_against_terraform"] is False, (
                f"{case['id']} is marked verified; update README.md, which states "
                f"that no case has been captured from a live terraform run"
            )


@pytest.mark.parametrize("case", CASES, ids=IDS)
class TestEveryCase:
    def test_the_plan_parses(self, case):
        parsed = plan_mod.load(CORPUS / case["plan"])
        assert parsed.format_version.startswith("1.")
        assert parsed.resource_changes

    def test_the_expected_rules_fire(self, case):
        parsed = plan_mod.load(CORPUS / case["plan"])
        report = cli.review(parsed, [case["analyzer"]], case.get("claim") or [])
        fired = {f.rule_id for f in report.findings}
        missing = set(case["expect"]) - fired
        assert not missing, f"{case['id']} did not report {sorted(missing)}; fired {sorted(fired)}"

    def test_the_forbidden_rules_do_not_fire(self, case):
        parsed = plan_mod.load(CORPUS / case["plan"])
        report = cli.review(parsed, [case["analyzer"]], case.get("claim") or [])
        fired = {f.rule_id for f in report.findings}
        wrong = fired & set(case["forbid"])
        assert not wrong, f"{case['id']} wrongly reported {sorted(wrong)}"

    def test_benign_controls_stay_under_their_ceiling(self, case):
        if not case["benign"]:
            pytest.skip("not a control")
        parsed = plan_mod.load(CORPUS / case["plan"])
        report = cli.review(parsed, [case["analyzer"]], case.get("claim") or [])
        ceiling = Severity.parse(case["max_severity"]) if case.get("max_severity") else None
        for f in report.findings:
            assert ceiling is not None and f.severity.rank <= ceiling.rank, (
                f"{case['id']} reported {f.rule_id} at {f.severity.value} on a benign change"
            )

    def test_every_finding_carries_evidence(self, case):
        parsed = plan_mod.load(CORPUS / case["plan"])
        report = cli.review(parsed, [case["analyzer"]], case.get("claim") or [])
        for f in report.findings:
            assert f.evidence, f"{case['id']}/{f.rule_id} has no evidence"
            assert f.remediation, f"{case['id']}/{f.rule_id} has no remediation"


class TestTheCorpusIsActuallyCommitted:
    """Regression: an unanchored `plan.json` in .gitignore hid the whole corpus.

    Every case file existed on disk, every test passed locally, and the pushed
    repository contained only the HCL. CI would then fail on a clone for reasons
    that look nothing like the cause.
    """

    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, cwd=ROOT
        )

    @pytest.fixture(autouse=True)
    def _requires_git_repo(self):
        if not (ROOT / ".git").exists():
            pytest.skip("not a git checkout")
        if self._git("--version").returncode != 0:
            pytest.skip("git not available")

    def test_no_corpus_file_is_ignored(self):
        paths = [
            str(p.relative_to(ROOT))
            for case in CASES
            for p in (CORPUS / case["plan"], CORPUS / case["terraform"])
        ]
        result = self._git("check-ignore", *paths)
        # check-ignore exits 1 when nothing matched, which is what we want.
        assert result.returncode == 1, (
            "these corpus files are excluded by .gitignore:\n" + result.stdout
        )

    def test_the_manifest_is_not_ignored(self):
        result = self._git("check-ignore", str(MANIFEST.relative_to(ROOT)))
        assert result.returncode == 1, result.stdout


class TestRuleCoverage:
    def test_every_rule_the_analyzers_emit_is_documented_by_a_case(self):
        """A rule with no corpus case is a rule nobody has ever seen fire."""
        emitted: set[str] = set()
        for case in CASES:
            parsed = plan_mod.load(CORPUS / case["plan"])
            report = cli.review(parsed, [case["analyzer"]], case.get("claim") or [])
            emitted |= {f.rule_id for f in report.findings}

        expected_by_corpus: set[str] = set()
        for case in CASES:
            expected_by_corpus |= set(case["expect"])

        undocumented = emitted - expected_by_corpus
        assert not undocumented, f"rules fire but no case declares them: {sorted(undocumented)}"


class TestBenchmark:
    def _run(self) -> str:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "benchmark.py"), "--json"],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    def test_the_benchmark_passes(self):
        summary = json.loads(self._run())["summary"]
        assert summary["misses"] == []
        assert summary["false_alarm_detail"] == []

    def test_the_benchmark_is_deterministic(self):
        """Two runs on the same commit must be byte-identical.

        This is what makes it legitimate to quote its numbers in the README.
        """
        assert self._run() == self._run()

    def test_the_benchmark_reports_the_corpus_size(self):
        summary = json.loads(self._run())["summary"]
        assert summary["corpus"]["dangerous_cases"] == sum(1 for c in CASES if not c["benign"])

    def test_the_readme_numbers_match_the_benchmark(self):
        """Enforces the project's first rule: no figure without a script.

        Every count quoted in README.md must be one this run produces. If a rule
        is added, or a corpus case, the README stops matching and this fails
        rather than quietly becoming wrong.
        """
        summary = json.loads(self._run())["summary"]
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        total = summary["corpus"]["dangerous_cases"] + summary["corpus"]["benign_controls"]

        expected = [
            f"{summary['corpus']['dangerous_cases']} dangerous cases",
            f"{summary['corpus']['benign_controls']} benign controls",
            f"{summary['detection']['cases_fully_detected']}/"
            f"{summary['corpus']['dangerous_cases']} dangerous cases fully detected",
            f"{summary['false_alarms']['cases_with_a_false_alarm']}/{total} cases",
            f"cases captured from a real terraform plan: "
            f"{summary['corpus']['cases_verified_against_real_terraform']}/{total}",
        ]
        missing = [phrase for phrase in expected if phrase not in readme]
        assert not missing, f"README.md does not quote the current numbers: {missing}"

    def test_the_readme_test_count_is_the_real_one(self):
        """The suite counts itself, so the README figure cannot rot unnoticed.

        Adding a test changes this number and fails this test until README.md is
        updated. That is the intended cost of claiming a figure in a README.
        """
        result = subprocess.run(
            # -o addopts="" drops the -q configured in pyproject.toml, which
            # would otherwise suppress the summary line this parses.
            [sys.executable, "-m", "pytest", "--collect-only", "-o", "addopts="],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        match = re.search(r"(\d+) tests collected", result.stdout)
        assert match, result.stdout[-2000:]
        collected = int(match.group(1))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        assert f"**{collected} tests" in readme, (
            f"README.md must say '{collected} tests'; collected {collected}"
        )

    def test_the_readme_documents_every_rule_the_corpus_exercises(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for case in CASES:
            for rule_id in case["expect"]:
                assert f"`{rule_id}`" in readme, f"{rule_id} is not in the README rule table"

    def test_the_readme_states_the_unimplemented_analyzers_up_front(self):
        """Rule: if something is not implemented, the README says so on screen one."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        first_screen = readme[: readme.index("## Why it exists")]
        assert "What is not here" in first_screen
        for absent in ("blast-radius", "privilege-escalation", "compliance-drift"):
            assert absent in first_screen, f"{absent} is not declared missing up front"

    def test_the_generator_is_idempotent(self):
        """Regenerating the corpus must not produce a diff."""
        before = {
            p: p.read_bytes()
            for p in sorted((CORPUS).rglob("*"))
            if p.is_file()
        }
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_corpus.py")],
            capture_output=True,
            check=True,
            cwd=ROOT,
        )
        after = {p: p.read_bytes() for p in sorted((CORPUS).rglob("*")) if p.is_file()}
        assert before == after
