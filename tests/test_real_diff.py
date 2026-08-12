"""Tests for the real-diff analyzer."""

from __future__ import annotations

from pyrrho.analyzers.real_diff import RealDiff
from pyrrho.core import Severity

from .conftest import change, make_plan, rule_ids


def run(changes, drift=None, claim=None):
    analyzer = RealDiff()
    if claim:
        analyzer.configure(claim=claim)
    return analyzer.run(make_plan(changes, drift))


class TestDataLoss:
    def test_deleting_a_database_is_critical(self):
        findings = run(
            [
                change(
                    "aws_db_instance.reports",
                    "aws_db_instance",
                    ["delete"],
                    before={"identifier": "reports-prod"},
                    after=None,
                    action_reason="delete_because_no_resource_config",
                )
            ]
        )
        assert rule_ids(findings) == {"RD001"}
        assert findings[0].severity is Severity.CRITICAL
        assert "the resource block was removed" in findings[0].evidence["action_reason"]

    def test_replacing_a_database_is_a_different_rule(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["delete", "create"],
                    before={"identifier": "orders", "db_subnet_group_name": "old"},
                    after={"identifier": "orders", "db_subnet_group_name": "new"},
                    replace_paths=[["db_subnet_group_name"]],
                    action_reason="replace_because_cannot_update",
                )
            ]
        )
        assert rule_ids(findings) == {"RD002"}
        assert "db_subnet_group_name" in findings[0].detail

    def test_the_final_snapshot_setting_is_carried_as_evidence(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["delete"],
                    before={"identifier": "orders", "skip_final_snapshot": True},
                    after=None,
                )
            ]
        )
        assert findings[0].evidence["skip_final_snapshot"]["before"] is True

    def test_a_kms_key_counts_as_stateful(self):
        findings = run(
            [change("aws_kms_key.backups", "aws_kms_key", ["delete"], before={"description": "x"}, after=None)]
        )
        assert rule_ids(findings) == {"RD001"}

    def test_destroying_a_stateless_resource_is_not_reported(self):
        findings = run(
            [change("aws_security_group.web", "aws_security_group", ["delete"], before={}, after=None)]
        )
        assert findings == []

    def test_replacing_a_launch_template_is_not_data_loss(self):
        findings = run(
            [
                change(
                    "aws_launch_template.workers",
                    "aws_launch_template",
                    ["delete", "create"],
                    before={"image_id": "ami-old"},
                    after={"image_id": "ami-new"},
                )
            ]
        )
        assert findings == []


class TestDowntime:
    def test_destroy_first_replacement_of_a_nat_gateway_is_reported(self):
        findings = run(
            [
                change(
                    "aws_nat_gateway.egress",
                    "aws_nat_gateway",
                    ["delete", "create"],
                    before={"allocation_id": "old"},
                    after={"allocation_id": "new"},
                )
            ]
        )
        assert rule_ids(findings) == {"RD003"}
        assert findings[0].severity is Severity.MEDIUM

    def test_create_before_destroy_removes_the_finding(self):
        findings = run(
            [
                change(
                    "aws_nat_gateway.egress",
                    "aws_nat_gateway",
                    ["create", "delete"],
                    before={"allocation_id": "old"},
                    after={"allocation_id": "new"},
                )
            ]
        )
        assert findings == []

    def test_a_plain_update_causes_no_downtime_finding(self):
        findings = run(
            [change("aws_lb.api", "aws_lb", ["update"], before={"name": "api"}, after={"name": "api"})]
        )
        assert findings == []


class TestGuards:
    def test_disabling_deletion_protection_is_reported(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"deletion_protection": True},
                    after={"deletion_protection": False},
                )
            ]
        )
        assert rule_ids(findings) == {"RD004"}
        assert findings[0].severity is Severity.HIGH

    def test_enabling_deletion_protection_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"deletion_protection": False},
                    after={"deletion_protection": True},
                )
            ]
        )
        assert findings == []

    def test_enabling_skip_final_snapshot_is_reported(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"skip_final_snapshot": False},
                    after={"skip_final_snapshot": True},
                )
            ]
        )
        assert rule_ids(findings) == {"RD004"}

    def test_enabling_force_destroy_on_a_bucket_is_reported(self):
        findings = run(
            [
                change(
                    "aws_s3_bucket.assets",
                    "aws_s3_bucket",
                    ["update"],
                    before={"force_destroy": False},
                    after={"force_destroy": True},
                )
            ]
        )
        assert rule_ids(findings) == {"RD004"}

    def test_both_guards_dropping_together_produces_two_findings(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"deletion_protection": True, "skip_final_snapshot": False},
                    after={"deletion_protection": False, "skip_final_snapshot": True},
                )
            ]
        )
        assert len(findings) == 2

    def test_the_two_guard_findings_are_independently_trackable(self):
        """Both are RD004 on one resource; they must not share a fingerprint."""
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"deletion_protection": True, "skip_final_snapshot": False},
                    after={"deletion_protection": False, "skip_final_snapshot": True},
                )
            ]
        )
        assert {f.key for f in findings} == {"deletion_protection", "skip_final_snapshot"}
        assert len({f.fingerprint for f in findings}) == 2

    def test_an_absent_guard_attribute_is_not_invented(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"instance_class": "db.t3.small"},
                    after={"instance_class": "db.t3.medium"},
                )
            ]
        )
        assert findings == []


class TestSensitiveValues:
    def test_a_changed_sensitive_value_is_reported(self):
        findings = run(
            [
                change(
                    "aws_secretsmanager_secret_version.key",
                    "aws_secretsmanager_secret_version",
                    ["update"],
                    before={"secret_string": "old"},
                    after={"secret_string": "new"},
                    before_sensitive={"secret_string": True},
                    after_sensitive={"secret_string": True},
                )
            ]
        )
        assert rule_ids(findings) == {"RD006"}

    def test_an_unchanged_sensitive_value_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_secretsmanager_secret_version.key",
                    "aws_secretsmanager_secret_version",
                    ["update"],
                    before={"secret_string": "same", "tags": {}},
                    after={"secret_string": "same", "tags": {"a": "b"}},
                    before_sensitive={"secret_string": True},
                    after_sensitive={"secret_string": True},
                )
            ]
        )
        assert findings == []

    def test_creation_does_not_report_sensitive_values(self):
        findings = run(
            [
                change(
                    "aws_secretsmanager_secret_version.key",
                    "aws_secretsmanager_secret_version",
                    ["create"],
                    after={"secret_string": "new"},
                    after_sensitive={"secret_string": True},
                )
            ]
        )
        assert findings == []


class TestUnknowns:
    def test_an_unknown_policy_is_reported(self):
        findings = run(
            [
                change(
                    "aws_s3_bucket_policy.assets",
                    "aws_s3_bucket_policy",
                    ["update"],
                    before={"policy": "{}"},
                    after={},
                    after_unknown={"policy": True},
                )
            ]
        )
        assert rule_ids(findings) == {"RD008"}

    def test_an_unknown_arn_is_not_security_relevant(self):
        findings = run(
            [
                change(
                    "aws_s3_bucket.assets",
                    "aws_s3_bucket",
                    ["create"],
                    after={},
                    after_unknown={"arn": True, "id": True},
                )
            ]
        )
        assert findings == []


class TestDrift:
    def test_drift_is_reported_once_for_the_whole_plan(self):
        findings = run(
            [change("aws_instance.web", "aws_instance", ["update"], before={}, after={})],
            drift=[change("aws_security_group.web", "aws_security_group", ["update"], before={}, after={})],
        )
        assert rule_ids(findings) == {"RD005"}
        assert findings[0].evidence["count"] == 1

    def test_no_drift_produces_nothing(self):
        findings = run([change("aws_instance.web", "aws_instance", ["update"], before={}, after={})])
        assert findings == []

    def test_no_op_drift_entries_are_ignored(self):
        findings = run(
            [change("aws_instance.web", "aws_instance", ["update"], before={}, after={})],
            drift=[change("aws_security_group.web", "aws_security_group", ["no-op"])],
        )
        assert findings == []


class TestScope:
    def test_resources_outside_the_claim_are_reported(self):
        findings = run(
            [
                change("aws_security_group.web", "aws_security_group", ["update"], before={}, after={}),
                change("aws_iam_role.ci", "aws_iam_role", ["update"], before={}, after={}),
            ],
            claim=["aws_security_group.*"],
        )
        assert rule_ids(findings) == {"RD007"}
        assert findings[0].evidence["unexpected_resources"] == ["aws_iam_role.ci"]

    def test_a_matching_plan_produces_nothing(self):
        findings = run(
            [change("aws_security_group.web", "aws_security_group", ["update"], before={}, after={})],
            claim=["aws_security_group.*"],
        )
        assert findings == []

    def test_no_claim_disables_the_rule(self):
        findings = run(
            [change("aws_iam_role.ci", "aws_iam_role", ["update"], before={}, after={})]
        )
        assert findings == []

    def test_multiple_patterns_are_all_honoured(self):
        findings = run(
            [
                change("aws_security_group.web", "aws_security_group", ["update"], before={}, after={}),
                change("aws_iam_role.ci", "aws_iam_role", ["update"], before={}, after={}),
            ],
            claim=["aws_security_group.*", "aws_iam_role.*"],
        )
        assert findings == []
