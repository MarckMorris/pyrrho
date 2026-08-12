"""Tests for the command line interface, especially the exit-code contract."""

from __future__ import annotations

import io
import json

from pyrrho import cli
from pyrrho.core import Severity

from .conftest import CORPUS, change, group, rule


def write_plan(tmp_path, changes, drift=None, name="plan.json"):
    doc = {"format_version": "1.2", "terraform_version": "1.9.8", "resource_changes": changes}
    if drift:
        doc["resource_drift"] = drift
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def open_ssh(tmp_path):
    return write_plan(
        tmp_path,
        [
            change(
                "aws_security_group.bastion",
                "aws_security_group",
                ["update"],
                before=group("bastion", [rule(22, 22, "tcp", ["10.0.0.0/8"])]),
                after=group("bastion", [rule(22, 22, "tcp", ["0.0.0.0/0"])]),
            )
        ],
    )


def clean_plan(tmp_path):
    return write_plan(
        tmp_path,
        [change("aws_instance.web", "aws_instance", ["update"], before={"instance_type": "a"}, after={"instance_type": "b"})],
        name="clean.json",
    )


class TestExitCodes:
    def test_a_clean_plan_exits_zero(self, tmp_path):
        code, _, _ = run([clean_plan(tmp_path)])
        assert code == cli.EXIT_OK

    def test_a_critical_finding_exits_one(self, tmp_path):
        code, _, _ = run([open_ssh(tmp_path)])
        assert code == cli.EXIT_BLOCKED

    def test_raising_the_threshold_above_the_finding_exits_zero(self, tmp_path):
        code, out, _ = run([clean_plan(tmp_path), "--fail-on", "low"])
        assert code == cli.EXIT_OK

    def test_a_finding_below_the_threshold_does_not_block(self, tmp_path):
        plan = write_plan(
            tmp_path,
            [
                change(
                    "aws_security_group.web",
                    "aws_security_group",
                    ["create"],
                    after=group("web", [rule(443, 443, "tcp", ["0.0.0.0/0"])]),
                )
            ],
        )
        code, out, _ = run([plan, "--fail-on", "high"])
        assert code == cli.EXIT_OK
        assert "WARN" in out

    def test_a_missing_plan_file_exits_two(self, tmp_path):
        code, _, err = run([str(tmp_path / "nope.json")])
        assert code == cli.EXIT_ERROR
        assert "not found" in err

    def test_no_arguments_exits_two(self):
        code, _, err = run([])
        assert code == cli.EXIT_ERROR
        assert "a plan file is required" in err

    def test_an_invalid_threshold_exits_two(self, tmp_path):
        code, _, err = run([clean_plan(tmp_path), "--fail-on", "apocalyptic"])
        assert code == cli.EXIT_ERROR
        assert "unknown severity" in err

    def test_an_unknown_analyzer_exits_two(self, tmp_path):
        code, _, err = run([clean_plan(tmp_path), "--analyzer", "telepathy"])
        assert code == cli.EXIT_ERROR
        assert "unknown analyzer" in err

    def test_state_json_is_rejected_with_an_explanation(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text(json.dumps({"format_version": "1.2", "values": {}}), encoding="utf-8")
        code, _, err = run([str(path)])
        assert code == cli.EXIT_ERROR
        assert "state, not a plan" in err


class TestOutputFormats:
    def test_json_output_is_parseable_and_carries_the_verdict(self, tmp_path):
        _, out, _ = run([open_ssh(tmp_path), "--format", "json"])
        payload = json.loads(out)
        assert payload["verdict"] == "block"
        assert payload["findings"][0]["rule_id"] == "NE001"
        assert payload["threshold"] == "high"

    def test_diagnostics_do_not_pollute_json_on_stdout(self, tmp_path):
        sarif_path = tmp_path / "out.sarif"
        _, out, err = run([open_ssh(tmp_path), "--format", "json", "--sarif", str(sarif_path)])
        json.loads(out)
        assert "wrote" in err

    def test_text_output_shows_evidence(self, tmp_path):
        _, out, _ = run([open_ssh(tmp_path)])
        assert "evidence" in out
        assert "previously_allowed" in out

    def test_quiet_prints_only_the_verdict(self, tmp_path):
        _, out, _ = run([open_ssh(tmp_path), "--quiet"])
        assert out.strip().startswith("BLOCK")
        assert "evidence" not in out

    def test_a_clean_plan_says_what_it_did_not_check(self, tmp_path):
        _, out, _ = run([clean_plan(tmp_path)])
        assert "only" in out and "analyzers cover" in out

    def test_list_analyzers_names_both(self):
        code, out, _ = run(["--list-analyzers"])
        assert code == cli.EXIT_OK
        assert "network-exposure" in out and "real-diff" in out


class TestAnalyzerSelection:
    def test_selecting_one_analyzer_excludes_the_other(self, tmp_path):
        plan = write_plan(
            tmp_path,
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"publicly_accessible": False, "deletion_protection": True},
                    after={"publicly_accessible": True, "deletion_protection": False},
                )
            ],
        )
        _, out, _ = run([plan, "--analyzer", "network-exposure", "--format", "json"])
        rules = {f["rule_id"] for f in json.loads(out)["findings"]}
        assert rules == {"NE006"}

    def test_both_analyzers_run_by_default(self, tmp_path):
        plan = write_plan(
            tmp_path,
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"publicly_accessible": False, "deletion_protection": True},
                    after={"publicly_accessible": True, "deletion_protection": False},
                )
            ],
        )
        _, out, _ = run([plan, "--format", "json"])
        rules = {f["rule_id"] for f in json.loads(out)["findings"]}
        assert rules == {"NE006", "RD004"}

    def test_the_claim_flag_reaches_the_analyzer(self, tmp_path):
        plan = write_plan(
            tmp_path,
            [change("aws_iam_role.ci", "aws_iam_role", ["update"], before={}, after={})],
        )
        _, out, _ = run([plan, "--claim", "aws_security_group.*", "--format", "json"])
        rules = {f["rule_id"] for f in json.loads(out)["findings"]}
        assert "RD007" in rules


class TestBaselineFlow:
    def test_init_then_reuse_turns_a_block_into_a_pass(self, tmp_path):
        plan = open_ssh(tmp_path)
        baseline_path = tmp_path / "baseline.json"

        code, _, _ = run([plan, "--init-baseline", str(baseline_path)])
        assert code == cli.EXIT_OK
        assert baseline_path.exists()

        code, out, _ = run([plan, "--baseline", str(baseline_path)])
        assert code == cli.EXIT_OK
        assert "suppressed by baseline" in out

    def test_a_new_finding_still_blocks_with_a_baseline(self, tmp_path):
        first = open_ssh(tmp_path)
        baseline_path = tmp_path / "baseline.json"
        run([first, "--init-baseline", str(baseline_path)])

        second = write_plan(
            tmp_path,
            [
                change(
                    "aws_security_group.other",
                    "aws_security_group",
                    ["create"],
                    after=group("other", [rule(3306, 3306, "tcp", ["0.0.0.0/0"])]),
                )
            ],
            name="second.json",
        )
        code, _, _ = run([second, "--baseline", str(baseline_path)])
        assert code == cli.EXIT_BLOCKED

    def test_stale_baseline_entries_are_reported(self, tmp_path):
        baseline_path = tmp_path / "baseline.json"
        run([open_ssh(tmp_path), "--init-baseline", str(baseline_path)])
        code, _, err = run([clean_plan(tmp_path), "--baseline", str(baseline_path)])
        assert code == cli.EXIT_OK
        assert "no longer matches" in err

    def test_an_unreadable_baseline_exits_two(self, tmp_path):
        code, _, err = run([clean_plan(tmp_path), "--baseline", str(tmp_path / "absent.json")])
        assert code == cli.EXIT_ERROR


class TestArtifacts:
    def test_sarif_is_written_and_valid(self, tmp_path):
        path = tmp_path / "nested" / "out.sarif"
        run([open_ssh(tmp_path), "--sarif", str(path)])
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"]

    def test_sarif_location_overrides_the_anchor(self, tmp_path):
        path = tmp_path / "out.sarif"
        run([open_ssh(tmp_path), "--sarif", str(path), "--sarif-location", "infra/net.tf"])
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "infra/net.tf"

    def test_an_attestation_is_written(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PYRRHO_ATTEST_KEY", "ci-key")
        path = tmp_path / "attestation.json"
        run([open_ssh(tmp_path), "--attest", str(path)])
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert doc["signed"] is True
        assert doc["verdict"] == "block"

    def test_an_attestation_records_the_pass_verdict_too(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PYRRHO_ATTEST_KEY", raising=False)
        path = tmp_path / "attestation.json"
        run([clean_plan(tmp_path), "--attest", str(path)])
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert doc["verdict"] == "pass"
        assert doc["signed"] is False


class TestAgainstTheCorpus:
    def test_the_review_helper_works_on_a_corpus_file(self):
        from pyrrho import plan as plan_mod

        parsed = plan_mod.load(CORPUS / "cases" / "ne001-ssh-opened-to-the-internet" / "plan.json")
        report = cli.review(parsed, ["network-exposure"], [])
        assert {f.rule_id for f in report.findings} == {"NE001"}
        assert report.exceeds(Severity.HIGH)
