"""Tests for the comparison scoring.

Checkov is not a test dependency: installing it pulls a large tree and the
comparison itself runs in CI, not here. What is tested here is the scoring rule,
because a comparison whose scoring quietly favours the home team is worse than no
comparison at all.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "compare_checkov.py"


def load_script():
    spec = importlib.util.spec_from_file_location("compare_checkov", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["compare_checkov"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def compare():
    return load_script()


DANGEROUS = {"benign": False}
BENIGN = {"benign": True}


class TestScoring:
    def test_a_dangerous_case_needs_any_report_to_count_as_detected(self, compare):
        assert compare.score(DANGEROUS, ["ANYTHING"])["detected"] is True

    def test_a_dangerous_case_with_no_report_is_a_miss(self, compare):
        assert compare.score(DANGEROUS, [])["detected"] is False

    def test_a_dangerous_case_cannot_produce_a_false_alarm(self, compare):
        # Reporting the wrong rule on a genuinely dangerous change is not noise.
        assert compare.score(DANGEROUS, ["WRONG_RULE"])["quiet"] is True

    def test_a_benign_control_with_no_report_is_quiet(self, compare):
        assert compare.score(BENIGN, [])["quiet"] is True

    def test_any_report_on_a_benign_control_is_a_false_alarm(self, compare):
        assert compare.score(BENIGN, ["ANYTHING"])["quiet"] is False

    def test_a_benign_control_never_counts_as_a_miss(self, compare):
        assert compare.score(BENIGN, [])["detected"] is True

    def test_the_rule_is_symmetric(self, compare):
        """The same function scores both tools. There is no home-team branch."""
        for case in (DANGEROUS, BENIGN):
            for reported in ([], ["X"], ["X", "Y"]):
                assert compare.score(case, reported) == compare.score(case, list(reported))


class TestMethodologyIsDeclared:
    def test_the_excluded_check_is_named_and_justified(self, compare):
        assert compare.EXCLUDED_CHECKS == {"CKV2_AWS_5"}
        assert "artefact" in compare.__doc__

    def test_the_docstring_states_the_generosity_of_the_recall_rule(self, compare):
        doc = compare.__doc__.lower()
        assert "generous to checkov" in doc

    def test_the_readme_quotes_the_comparison_and_its_caveat(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        assert "Measured against Checkov" in readme
        assert "complements, not substitutes" in readme
        # The comparison must not be presented as a clean win.
        assert "Read that fairly" in readme


class TestCorpusIsToolNeutral:
    """The corpus must be readable by tools that ignore resource_changes.

    Most scanners read `planned_values`, which describes the post-apply state.
    Leaving it empty made every one of them see zero resources, which looked like
    a clean result and was really an unreadable file.
    """

    def test_planned_values_are_populated(self):
        import json

        manifest = json.loads((ROOT / "corpus" / "manifest.json").read_text(encoding="utf-8"))
        for case in manifest["cases"]:
            plan = json.loads((ROOT / "corpus" / case["plan"]).read_text(encoding="utf-8"))
            resources = plan["planned_values"]["root_module"]["resources"]
            creating = [
                rc
                for rc in plan["resource_changes"]
                if rc["change"]["actions"] not in (["delete"], ["no-op"])
                and rc["change"].get("after") is not None
            ]
            assert len(resources) == len(creating), case["id"]

    def test_destroyed_resources_are_absent_from_planned_values(self):
        import json

        plan = json.loads(
            (ROOT / "corpus" / "cases" / "rd001-production-database-destroyed" / "plan.json").read_text(
                encoding="utf-8"
            )
        )
        assert plan["planned_values"]["root_module"]["resources"] == []

    def test_planned_values_carry_the_planned_attributes(self):
        import json

        plan = json.loads(
            (ROOT / "corpus" / "cases" / "ne006-rds-made-publicly-accessible" / "plan.json").read_text(
                encoding="utf-8"
            )
        )
        resource = plan["planned_values"]["root_module"]["resources"][0]
        assert resource["type"] == "aws_db_instance"
        assert resource["values"]["publicly_accessible"] is True
