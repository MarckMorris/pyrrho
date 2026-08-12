"""Tests for the registry, the report container and the analyzer base class."""

from __future__ import annotations

import pytest

from pyrrho import core
from pyrrho.core import Analyzer, Finding, Report, Severity


def finding(**kw):
    defaults = dict(
        rule_id="XX001",
        title="t",
        severity=Severity.MEDIUM,
        analyzer="test",
        resource="aws_x.y",
        detail="d",
    )
    defaults.update(kw)
    return Finding(**defaults)


class TestRegistry:
    def test_both_analyzers_are_registered(self):
        assert core.available() == ["network-exposure", "real-diff"]

    def test_resolve_with_no_names_returns_everything(self):
        assert len(core.resolve(None)) == 2

    def test_resolve_honours_a_single_name(self):
        resolved = core.resolve(["real-diff"])
        assert [a.name for a in resolved] == ["real-diff"]

    def test_resolve_rejects_an_unknown_name_and_lists_the_valid_ones(self):
        with pytest.raises(ValueError, match="network-exposure"):
            core.resolve(["telepathy"])

    def test_an_analyzer_without_a_name_cannot_register(self):
        class Nameless(Analyzer):
            pass

        with pytest.raises(ValueError, match="must define a name"):
            core.register(Nameless)

    def test_a_duplicate_name_cannot_register(self):
        class Duplicate(Analyzer):
            name = "real-diff"

        with pytest.raises(ValueError, match="duplicate analyzer name"):
            core.register(Duplicate)

    def test_the_base_class_refuses_to_run(self):
        with pytest.raises(NotImplementedError):
            Analyzer().run(object())

    def test_configure_is_a_no_op_by_default(self):
        assert Analyzer().configure(anything=True) is None

    def test_the_finding_helper_stamps_the_analyzer_name(self):
        class Example(Analyzer):
            name = "example-only-in-this-test"

        f = Example().finding("X1", "t", Severity.LOW, "aws_x.y", "d")
        assert f.analyzer == "example-only-in-this-test"
        assert f.evidence == {}


class TestReport:
    def test_a_report_is_iterable_and_sized(self):
        report = Report(findings=[finding(), finding(resource="aws_x.z")])
        assert len(report) == 2
        assert len(list(report)) == 2

    def test_add_and_extend_both_work(self):
        report = Report()
        report.add(finding())
        report.extend([finding(resource="aws_x.z")])
        assert len(report) == 2

    def test_worst_is_none_when_empty(self):
        assert Report().worst is None

    def test_worst_ignores_suppressed_findings(self):
        report = Report(findings=[finding(severity=Severity.CRITICAL, suppressed=True)])
        assert report.worst is None

    def test_worst_picks_the_highest(self):
        report = Report(
            findings=[finding(severity=Severity.LOW), finding(rule_id="XX002", severity=Severity.HIGH)]
        )
        assert report.worst is Severity.HIGH

    def test_exceeds_is_false_on_an_empty_report(self):
        assert not Report().exceeds(Severity.INFO)

    def test_by_severity_counts_only_what_counts(self):
        report = Report(
            findings=[
                finding(severity=Severity.HIGH),
                finding(rule_id="XX002", severity=Severity.HIGH, suppressed=True),
            ]
        )
        assert report.by_severity()["high"] == 1

    def test_to_dict_is_json_shaped(self):
        report = Report(plan_path="p.json", findings=[finding()])
        payload = report.to_dict()
        assert payload["plan"]["path"] == "p.json"
        assert payload["findings"][0]["rule_id"] == "XX001"
        assert payload["by_severity"]["medium"] == 1

    def test_canonical_json_is_stable_across_equal_reports(self):
        a = Report(plan_path="p.json", findings=[finding()])
        b = Report(plan_path="p.json", findings=[finding()])
        assert a.canonical_json() == b.canonical_json()

    def test_canonical_json_changes_when_a_finding_changes(self):
        a = Report(findings=[finding()])
        b = Report(findings=[finding(severity=Severity.HIGH)])
        assert a.canonical_json() != b.canonical_json()
