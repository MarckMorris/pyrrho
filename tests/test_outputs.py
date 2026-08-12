"""Tests for SARIF, baseline and attestation output."""

from __future__ import annotations

import json

import pytest

from pyrrho import attest, baseline, sarif
from pyrrho.core import Finding, Report, Severity, Verdict


def finding(rule_id="NE001", resource="aws_security_group.web", severity=Severity.CRITICAL, **kw):
    return Finding(
        rule_id=rule_id,
        title=kw.get("title", "Something is open"),
        severity=severity,
        analyzer=kw.get("analyzer", "network-exposure"),
        resource=resource,
        detail=kw.get("detail", "detail text"),
        evidence=kw.get("evidence", {"ports": "tcp/22"}),
        remediation=kw.get("remediation", "close it"),
        suppressed=kw.get("suppressed", False),
        key=kw.get("key", ""),
    )


def report(findings=None, **kw):
    return Report(
        plan_path=kw.get("plan_path", "plan.json"),
        plan_digest=kw.get("plan_digest", "a" * 64),
        terraform_version="1.9.8",
        format_version="1.2",
        analyzers=["network-exposure", "real-diff"],
        findings=list(findings or []),
        resources_examined=kw.get("resources_examined", 3),
    )


class TestSeverityAndVerdict:
    def test_severity_orders_correctly(self):
        assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_parse_is_case_insensitive_and_trims(self):
        assert Severity.parse("  HIGH ") is Severity.HIGH

    def test_parse_rejects_junk_with_a_useful_message(self):
        with pytest.raises(ValueError, match="expected one of"):
            Severity.parse("catastrophic")

    def test_no_findings_is_a_pass(self):
        assert report().verdict(Severity.HIGH) is Verdict.PASS

    def test_findings_below_the_threshold_warn_but_do_not_block(self):
        r = report([finding(severity=Severity.LOW)])
        assert r.verdict(Severity.HIGH) is Verdict.WARN

    def test_findings_at_the_threshold_block(self):
        r = report([finding(severity=Severity.HIGH)])
        assert r.verdict(Severity.HIGH) is Verdict.BLOCK

    def test_suppressed_findings_do_not_block(self):
        r = report([finding(severity=Severity.CRITICAL, suppressed=True)])
        assert r.verdict(Severity.HIGH) is Verdict.PASS

    def test_findings_sort_most_severe_first(self):
        r = report([finding(rule_id="NE009", severity=Severity.MEDIUM), finding(rule_id="NE001")])
        assert [f.rule_id for f in r.sorted_findings()] == ["NE001", "NE009"]

    def test_sorting_is_deterministic_for_equal_severities(self):
        a = finding(rule_id="NE002", resource="b")
        b = finding(rule_id="NE002", resource="a")
        assert [f.resource for f in report([a, b]).sorted_findings()] == ["a", "b"]


class TestFingerprints:
    def test_the_same_problem_keeps_its_identity(self):
        assert finding(detail="one").fingerprint == finding(detail="two").fingerprint

    def test_a_different_resource_is_a_different_finding(self):
        assert finding(resource="a").fingerprint != finding(resource="b").fingerprint

    def test_a_different_rule_is_a_different_finding(self):
        assert finding(rule_id="NE001").fingerprint != finding(rule_id="NE002").fingerprint

    def test_two_aspects_of_one_rule_on_one_resource_stay_apart(self):
        """Regression: without the key these collapsed into a single alert.

        A database can drop deletion protection and enable skip_final_snapshot in
        the same change. Both are RD004 on the same address. Sharing a
        fingerprint meant GitHub showed one alert, and baselining either one
        silently suppressed the other.
        """
        a = finding(rule_id="RD004", key="deletion_protection")
        b = finding(rule_id="RD004", key="skip_final_snapshot")
        assert a.fingerprint != b.fingerprint


class TestSarif:
    def test_the_document_is_valid_sarif_shape(self):
        doc = sarif.to_sarif(report([finding()]))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "pyrrho"
        assert len(doc["runs"][0]["results"]) == 1

    def test_severity_maps_to_a_github_level_and_score(self):
        doc = sarif.to_sarif(report([finding(severity=Severity.CRITICAL)]))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["properties"]["security-severity"] == "9.5"

    def test_a_low_finding_is_a_note(self):
        doc = sarif.to_sarif(report([finding(severity=Severity.LOW)]))
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_each_rule_appears_once_in_the_catalogue(self):
        doc = sarif.to_sarif(report([finding(resource="a"), finding(resource="b")]))
        assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(doc["runs"][0]["results"]) == 2

    def test_evidence_travels_with_the_result(self):
        doc = sarif.to_sarif(report([finding(evidence={"ports": "tcp/22"})]))
        assert doc["runs"][0]["results"][0]["properties"]["evidence"] == {"ports": "tcp/22"}

    def test_suppressed_findings_stay_visible_but_marked(self):
        doc = sarif.to_sarif(report([finding(suppressed=True)]))
        result = doc["runs"][0]["results"][0]
        assert result["suppressions"][0]["kind"] == "external"

    def test_the_location_defaults_to_the_plan_path(self):
        doc = sarif.to_sarif(report([finding()]))
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "plan.json"

    def test_the_location_can_be_pointed_at_source(self):
        doc = sarif.to_sarif(report([finding()]), location="infra/network.tf")
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "infra/network.tf"

    def test_an_empty_report_still_produces_a_valid_document(self):
        doc = sarif.to_sarif(report([]))
        assert doc["runs"][0]["results"] == []

    def test_output_is_json_serialisable(self):
        json.loads(sarif.dumps(report([finding()])))


class TestBaseline:
    def test_a_baseline_round_trips(self, tmp_path):
        r = report([finding()])
        path = tmp_path / "baseline.json"
        path.write_text(baseline.dumps(r), encoding="utf-8")
        assert baseline.load(path) == {r.findings[0].fingerprint}

    def test_entries_keep_human_context(self):
        doc = baseline.build(report([finding()]))
        entry = doc["entries"][0]
        assert entry["rule_id"] == "NE001"
        assert entry["resource"] == "aws_security_group.web"

    def test_applying_a_baseline_suppresses_without_deleting(self):
        r = report([finding()])
        r = baseline.apply(r, {r.findings[0].fingerprint})
        assert len(r.findings) == 1
        assert r.findings[0].suppressed
        assert r.counted == []

    def test_a_non_matching_baseline_changes_nothing(self):
        r = baseline.apply(report([finding()]), {"deadbeefdeadbeef"})
        assert not r.findings[0].suppressed

    def test_stale_entries_are_identified(self):
        r = report([finding()])
        stale = baseline.stale(r, {r.findings[0].fingerprint, "0000000000000000"})
        assert stale == {"0000000000000000"}

    def test_a_missing_file_says_how_to_create_one(self, tmp_path):
        with pytest.raises(baseline.BaselineError, match="--init-baseline"):
            baseline.load(tmp_path / "absent.json")

    def test_invalid_json_is_rejected(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text("{oops", encoding="utf-8")
        with pytest.raises(baseline.BaselineError, match="not valid JSON"):
            baseline.load(path)

    def test_a_foreign_file_is_rejected(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"format": "something-else"}), encoding="utf-8")
        with pytest.raises(baseline.BaselineError, match="not a pyrrho baseline"):
            baseline.load(path)

    def test_entries_must_be_a_list(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"format": baseline.FORMAT, "entries": {}}), encoding="utf-8")
        with pytest.raises(baseline.BaselineError, match="no 'entries' list"):
            baseline.load(path)


class TestAttestation:
    def test_an_unsigned_record_says_so(self, monkeypatch):
        monkeypatch.delenv(attest.KEY_ENV, raising=False)
        doc = attest.build(report([finding()]), Severity.HIGH, Verdict.BLOCK)
        assert doc["signed"] is False
        assert doc["signature"] is None
        assert "not set" in doc["unsigned_reason"]

    def test_a_key_produces_a_signature(self):
        doc = attest.build(report([finding()]), Severity.HIGH, Verdict.BLOCK, key="s3cret")
        assert doc["signed"] is True
        assert doc["signature"]["algorithm"] == "HMAC-SHA256"

    def test_a_signature_verifies(self):
        doc = attest.build(report([finding()]), Severity.HIGH, Verdict.BLOCK, key="s3cret")
        ok, reason = attest.verify(doc, key="s3cret")
        assert ok, reason

    def test_a_tampered_verdict_fails_verification(self):
        doc = attest.build(report([finding()]), Severity.HIGH, Verdict.BLOCK, key="s3cret")
        doc["verdict"] = "pass"
        ok, reason = attest.verify(doc, key="s3cret")
        assert not ok
        assert "altered" in reason

    def test_a_different_key_fails_verification(self):
        doc = attest.build(report([finding()]), Severity.HIGH, Verdict.BLOCK, key="s3cret")
        ok, _ = attest.verify(doc, key="other")
        assert not ok

    def test_an_unsigned_record_cannot_be_verified(self, monkeypatch):
        monkeypatch.delenv(attest.KEY_ENV, raising=False)
        doc = attest.build(report([finding()]), Severity.HIGH, Verdict.BLOCK)
        ok, reason = attest.verify(doc)
        assert not ok
        assert "unsigned" in reason

    def test_a_foreign_document_is_rejected(self):
        ok, reason = attest.verify({"format": "nope"})
        assert not ok and "not a pyrrho attestation" in reason

    def test_the_key_is_read_from_the_environment(self, monkeypatch):
        monkeypatch.setenv(attest.KEY_ENV, "from-env")
        doc = attest.build(report([finding()]), Severity.HIGH, Verdict.BLOCK)
        assert attest.verify(doc)[0]

    def test_the_record_binds_the_plan_and_the_rules_that_ran(self):
        doc = attest.build(report([finding()]), Severity.HIGH, Verdict.BLOCK, key="k")
        assert doc["plan"]["sha256"] == "a" * 64
        assert doc["analyzers"] == ["network-exposure", "real-diff"]
        assert doc["threshold"] == "high"

    def test_the_timestamp_can_be_pinned_for_reproducibility(self):
        doc = attest.build(
            report([finding()]), Severity.HIGH, Verdict.BLOCK, timestamp="2026-01-01T00:00:00+00:00"
        )
        assert doc["reviewed_at"] == "2026-01-01T00:00:00+00:00"

    def test_two_identical_reports_attest_identically(self):
        args = (Severity.HIGH, Verdict.BLOCK, "2026-01-01T00:00:00+00:00", "k")
        assert attest.dumps(report([finding()]), *args) == attest.dumps(report([finding()]), *args)
