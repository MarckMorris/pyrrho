"""Tests for the IAM analyzer and the policy diffing it rests on.

The delta is the whole point here. Every test that asserts *nothing* is reported
matters as much as the ones that assert a finding: a policy that already granted
something is not this pull request's problem.
"""

from __future__ import annotations

import json

import pytest

from pyrrho import policy
from pyrrho.analyzers.privilege_escalation import PrivilegeEscalation
from pyrrho.core import Severity

from .conftest import change, make_plan, rule_ids


def run(changes):
    return PrivilegeEscalation().run(make_plan(changes))


def doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def allow(actions, resources="*", **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **extra}


def policy_change(before_doc, after_doc, type_="aws_iam_policy", address="aws_iam_policy.p"):
    return change(
        address,
        type_,
        ["update"] if before_doc is not None else ["create"],
        before={"name": "p", "policy": before_doc} if before_doc is not None else None,
        after={"name": "p", "policy": after_doc},
    )


class TestPolicyParsing:
    def test_a_scalar_action_becomes_a_list(self):
        [statement] = policy.parse(doc(allow("s3:GetObject")))
        assert statement.actions == ("s3:GetObject",)

    def test_a_principal_string_and_a_principal_map_are_the_same(self):
        a = policy.parse(doc(allow("sts:AssumeRole", Principal="*")))[0]
        b = policy.parse(doc(allow("sts:AssumeRole", Principal={"AWS": "*"})))[0]
        assert a.principals == b.principals == ("*",)

    def test_a_principal_map_with_a_list_is_flattened(self):
        [s] = policy.parse(doc(allow("sts:AssumeRole", Principal={"AWS": ["a", "b"]})))
        assert set(s.principals) == {"a", "b"}

    @pytest.mark.parametrize("junk", ["", "   ", "not json", "[]", None, 42])
    def test_unusable_input_yields_no_statements_rather_than_raising(self, junk):
        assert policy.parse(junk) == []

    def test_an_already_parsed_dict_is_accepted(self):
        assert len(policy.parse({"Statement": [allow("s3:*")]})) == 1

    def test_a_non_dict_statement_is_skipped(self):
        assert policy.parse(json.dumps({"Statement": ["nonsense", allow("s3:*")]})) == policy.parse(
            doc(allow("s3:*"))
        )

    def test_a_missing_effect_defaults_to_allow(self):
        [s] = policy.parse(json.dumps({"Statement": [{"Action": "s3:*", "Resource": "*"}]}))
        assert s.allows


class TestActionMatching:
    def test_an_exact_action_matches(self):
        [s] = policy.parse(doc(allow("iam:PassRole")))
        assert s.matches_action("iam:PassRole")

    def test_a_service_glob_matches(self):
        [s] = policy.parse(doc(allow("iam:*")))
        assert s.matches_action("iam:PassRole")

    def test_a_full_wildcard_matches_everything(self):
        [s] = policy.parse(doc(allow("*")))
        assert s.matches_action("anything:AtAll")

    def test_matching_ignores_case(self):
        [s] = policy.parse(doc(allow("IAM:passrole")))
        assert s.matches_action("iam:PassRole")

    def test_an_unrelated_action_does_not_match(self):
        [s] = policy.parse(doc(allow("s3:GetObject")))
        assert not s.matches_action("iam:PassRole")


class TestPolicyDiff:
    def test_an_added_statement_is_reported_as_added(self):
        delta = policy.diff(policy.parse(doc(allow("s3:*"))), policy.parse(doc(allow("s3:*"), allow("iam:*"))))
        assert len(delta.added) == 1
        assert delta.added[0].actions == ("iam:*",)

    def test_an_unchanged_policy_produces_an_empty_delta(self):
        same = policy.parse(doc(allow("s3:*")))
        assert policy.diff(same, list(same)).empty

    def test_a_removed_condition_is_a_weakening_not_an_add_and_a_remove(self):
        before = policy.parse(doc(allow("ec2:*", Sid="X", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})))
        after = policy.parse(doc(allow("ec2:*", Sid="X")))
        delta = policy.diff(before, after)
        assert delta.added == [] and delta.removed == []
        assert len(delta.weakened) == 1

    def test_gaining_an_action_on_a_named_statement_is_a_weakening(self):
        before = policy.parse(doc(allow(["s3:GetObject"], Sid="X")))
        after = policy.parse(doc(allow(["s3:GetObject", "s3:DeleteObject"], Sid="X")))
        assert len(policy.diff(before, after).weakened) == 1

    def test_a_narrowed_statement_is_not_a_weakening(self):
        before = policy.parse(doc(allow(["s3:GetObject", "s3:DeleteObject"], Sid="X")))
        after = policy.parse(doc(allow(["s3:GetObject"], Sid="X")))
        assert policy.diff(before, after).weakened == []

    def test_statements_without_a_sid_pair_on_their_shape(self):
        before = policy.parse(doc(allow("s3:*", Condition={"Bool": {"x": "true"}})))
        after = policy.parse(doc(allow("s3:*")))
        assert len(policy.diff(before, after).weakened) == 1


class TestWildcards:
    def test_star_on_star_is_critical(self):
        findings = run([policy_change(doc(allow("s3:GetObject")), doc(allow("s3:GetObject"), allow("*")))])
        assert "PE001" in rule_ids(findings)
        assert findings[0].severity is Severity.CRITICAL

    def test_a_preexisting_wildcard_is_not_reported(self):
        """The delta discipline, for IAM."""
        before = doc(allow("*"))
        findings = run([policy_change(before, before)])
        assert findings == []

    def test_narrowing_a_wildcard_reports_nothing(self):
        findings = run([policy_change(doc(allow("*", Sid="X")), doc(allow(["s3:GetObject"], "arn:aws:s3:::b/*", Sid="X")))])
        assert findings == []

    def test_a_scoped_wildcard_action_is_high_not_critical(self):
        findings = run([policy_change(None, doc(allow("*", ["arn:aws:s3:::b/*"])))])
        assert [f.severity for f in findings if f.rule_id == "PE001"] == [Severity.HIGH]

    def test_a_deny_with_a_wildcard_is_not_a_grant(self):
        findings = run([policy_change(None, doc({"Effect": "Deny", "Action": "*", "Resource": "*"}))])
        assert findings == []


class TestPassRole:
    def test_passrole_on_a_wildcard_is_critical(self):
        findings = run([policy_change(None, doc(allow(["ec2:RunInstances", "iam:PassRole"])))])
        pe002 = [f for f in findings if f.rule_id == "PE002"]
        assert pe002 and pe002[0].severity is Severity.CRITICAL
        assert "ec2:RunInstances" in pe002[0].evidence["paired_with"]

    def test_passrole_scoped_to_named_roles_is_medium(self):
        findings = run(
            [policy_change(None, doc(allow(["iam:PassRole"], ["arn:aws:iam::111122223333:role/app"])))]
        )
        pe002 = [f for f in findings if f.rule_id == "PE002"]
        assert pe002 and pe002[0].severity is Severity.MEDIUM

    def test_passrole_reached_through_a_service_glob_is_caught(self):
        findings = run([policy_change(None, doc(allow(["iam:*"])))])
        assert "PE002" in rule_ids(findings)


class TestTrustPolicies:
    def trust(self, before_principal, after_principal, condition=None):
        def document(principal):
            statement = {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"}
            if condition:
                statement["Condition"] = condition
            return json.dumps({"Version": "2012-10-17", "Statement": [statement]})

        return change(
            "aws_iam_role.r",
            "aws_iam_role",
            ["update"] if before_principal else ["create"],
            before={"name": "r", "assume_role_policy": document(before_principal)} if before_principal else None,
            after={"name": "r", "assume_role_policy": document(after_principal)},
        )

    def test_opening_a_trust_policy_to_anyone_is_critical(self):
        findings = run([self.trust("arn:aws:iam::111122223333:root", "*")])
        assert rule_ids(findings) == {"PE003"}
        assert findings[0].severity is Severity.CRITICAL

    def test_a_named_role_principal_is_not_reported(self):
        findings = run([self.trust(None, "arn:aws:iam::444455556666:role/vendor")])
        assert findings == []

    def test_a_wildcard_with_a_condition_is_high_not_critical(self):
        findings = run(
            [self.trust(None, "*", condition={"StringEquals": {"sts:ExternalId": "s3cret"}})]
        )
        assert findings[0].severity is Severity.HIGH

    def test_an_account_root_principal_is_reported(self):
        # ":root" means every identity in that account, not one role.
        findings = run([self.trust(None, "arn:aws:iam::444455556666:root")])
        assert rule_ids(findings) == {"PE003"}

    def test_a_trust_policy_that_does_not_change_is_not_reported(self):
        findings = run([self.trust("*", "*")])
        assert findings == []


class TestEscalationPrimitives:
    def test_a_new_primitive_is_reported(self):
        findings = run(
            [
                policy_change(
                    doc(allow(["s3:GetObject"])),
                    doc(allow(["s3:GetObject"]), allow(["iam:CreatePolicyVersion"], ["arn:aws:iam::1:policy/*"])),
                )
            ]
        )
        assert "PE004" in rule_ids(findings)

    def test_a_primitive_the_identity_already_had_is_not_re_reported(self):
        before = doc(allow(["iam:CreateAccessKey"], Sid="A"))
        after = doc(allow(["iam:CreateAccessKey"], Sid="A"), allow(["iam:CreateAccessKey"], Sid="B"))
        findings = [f for f in run([policy_change(before, after)]) if f.rule_id == "PE004"]
        assert findings == []

    def test_a_full_wildcard_reports_pe001_not_a_list_of_primitives(self):
        findings = run([policy_change(None, doc(allow("*")))])
        assert "PE001" in rule_ids(findings)
        assert "PE004" not in rule_ids(findings)

    def test_the_finding_explains_what_the_primitive_actually_does(self):
        findings = run([policy_change(None, doc(allow(["lambda:UpdateFunctionCode"])))])
        pe004 = [f for f in findings if f.rule_id == "PE004"][0]
        assert "replace the code" in pe004.detail


class TestConditions:
    def test_a_removed_condition_is_reported(self):
        before = doc(allow(["ec2:TerminateInstances"], Sid="Op", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}))
        after = doc(allow(["ec2:TerminateInstances"], Sid="Op"))
        findings = [f for f in run([policy_change(before, after)]) if f.rule_id == "PE005"]
        assert findings and findings[0].severity is Severity.HIGH
        assert "aws:MultiFactorAuthPresent" in str(findings[0].evidence["conditions_before"])

    def test_adding_a_condition_is_not_reported(self):
        before = doc(allow(["ec2:TerminateInstances"], Sid="Op"))
        after = doc(allow(["ec2:TerminateInstances"], Sid="Op", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}))
        assert [f for f in run([policy_change(before, after)]) if f.rule_id == "PE005"] == []


class TestNotActionAndNotResource:
    def test_an_allow_with_notaction_is_reported(self):
        findings = run([policy_change(None, json.dumps({"Statement": [{"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}]}))])
        assert "PE006" in rule_ids(findings)

    def test_a_deny_with_notaction_is_not_reported(self):
        findings = run([policy_change(None, json.dumps({"Statement": [{"Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}]}))])
        assert findings == []


class TestManagedAttachments:
    def attach(self, arn, before_arn=None):
        return change(
            "aws_iam_role_policy_attachment.a",
            "aws_iam_role_policy_attachment",
            ["update"] if before_arn else ["create"],
            before={"role": "r", "policy_arn": before_arn} if before_arn else None,
            after={"role": "r", "policy_arn": arn},
        )

    def test_administrator_access_is_critical(self):
        findings = run([self.attach("arn:aws:iam::aws:policy/AdministratorAccess")])
        assert rule_ids(findings) == {"PE007"}
        assert findings[0].severity is Severity.CRITICAL

    def test_power_user_access_is_high(self):
        findings = run([self.attach("arn:aws:iam::aws:policy/PowerUserAccess")])
        assert findings[0].severity is Severity.HIGH

    def test_an_ordinary_managed_policy_is_not_reported(self):
        findings = run([self.attach("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")])
        assert findings == []

    def test_detaching_administrator_access_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_iam_role_policy_attachment.a",
                    "aws_iam_role_policy_attachment",
                    ["delete"],
                    before={"role": "r", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                    after=None,
                )
            ]
        )
        assert findings == []


class TestUnknownPolicies:
    def test_a_policy_unknown_until_apply_is_reported(self):
        findings = run(
            [
                change(
                    "aws_iam_policy.p",
                    "aws_iam_policy",
                    ["update"],
                    before={"name": "p", "policy": "{}"},
                    after={"name": "p"},
                    after_unknown={"policy": True},
                )
            ]
        )
        assert rule_ids(findings) == {"PE008"}


class TestRobustness:
    def test_an_unparseable_policy_does_not_crash(self):
        assert run([policy_change(None, "{not json")]) == []

    def test_a_resource_with_no_policy_attribute_is_ignored(self):
        assert run([change("aws_iam_policy.p", "aws_iam_policy", ["create"], after={"name": "p"})]) == []

    def test_unrelated_resources_produce_nothing(self):
        assert run([change("aws_s3_bucket.b", "aws_s3_bucket", ["create"], after={"bucket": "b"})]) == []

    def test_every_finding_carries_evidence_and_a_fix(self):
        findings = run([policy_change(None, doc(allow("*"), allow(["iam:PassRole"])))])
        assert findings
        for f in findings:
            assert f.evidence and f.remediation
