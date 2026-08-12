"""Tests for reading Terraform's plan JSON, including its sharper edges."""

from __future__ import annotations

import json

import pytest

from pyrrho import plan as plan_mod
from pyrrho.plan import PlanFormatError

from .conftest import change, make_plan


class TestRejectingBadInput:
    def test_a_json_array_is_rejected(self):
        with pytest.raises(PlanFormatError, match="JSON object"):
            plan_mod.loads("[]")

    def test_missing_format_version_names_the_right_command(self):
        with pytest.raises(PlanFormatError, match="terraform show -json"):
            plan_mod.loads(json.dumps({"resource_changes": []}))

    def test_a_future_major_format_is_refused_rather_than_guessed(self):
        with pytest.raises(PlanFormatError, match="not supported"):
            plan_mod.loads(json.dumps({"format_version": "2.0", "resource_changes": []}))

    def test_state_output_is_distinguished_from_plan_output(self):
        with pytest.raises(PlanFormatError, match="that is state, not a plan"):
            plan_mod.loads(json.dumps({"format_version": "1.2", "values": {}}))

    def test_invalid_json_explains_how_to_produce_valid_json(self):
        with pytest.raises(PlanFormatError, match="not valid JSON"):
            plan_mod.loads("{oops")

    def test_missing_file(self, tmp_path):
        with pytest.raises(PlanFormatError, match="plan file not found"):
            plan_mod.load(tmp_path / "nope.json")

    def test_a_directory_is_not_a_plan(self, tmp_path):
        with pytest.raises(PlanFormatError, match="expected a file"):
            plan_mod.load(tmp_path)


class TestActionSemantics:
    def test_destroy_then_create_is_a_replacement(self):
        rc = make_plan([change("a.b", "aws_instance", ["delete", "create"])]).resource_changes[0]
        assert rc.is_replace
        assert not rc.is_create_before_destroy
        assert rc.destroys_data
        assert rc.summary == "replace (destroy-then-create)"

    def test_create_then_destroy_is_a_replacement_without_a_gap(self):
        rc = make_plan([change("a.b", "aws_instance", ["create", "delete"])]).resource_changes[0]
        assert rc.is_replace
        assert rc.is_create_before_destroy
        assert rc.summary == "replace (create-then-destroy)"

    def test_a_plain_update_destroys_nothing(self):
        rc = make_plan([change("a.b", "aws_instance", ["update"])]).resource_changes[0]
        assert rc.is_update
        assert not rc.destroys_data

    def test_delete_destroys_data(self):
        rc = make_plan([change("a.b", "aws_instance", ["delete"])]).resource_changes[0]
        assert rc.is_delete and rc.destroys_data

    def test_no_op_and_read_are_excluded_from_effective_changes(self):
        plan = make_plan(
            [
                change("a.noop", "aws_instance", ["no-op"]),
                change("a.read", "aws_ami", ["read"]),
                change("a.real", "aws_instance", ["update"]),
            ]
        )
        assert [rc.address for rc in plan.effective_changes] == ["a.real"]


class TestUnknownAndSensitive:
    def test_a_true_marker_is_unknown(self):
        rc = make_plan(
            [change("a.b", "aws_security_group", ["create"], after={}, after_unknown={"ingress": True})]
        ).resource_changes[0]
        assert rc.is_unknown("ingress")

    def test_a_nested_marker_is_unknown(self):
        rc = make_plan(
            [change("a.b", "aws_x", ["create"], after={}, after_unknown={"tags": {"k": True}})]
        ).resource_changes[0]
        assert rc.is_unknown("tags")

    def test_an_empty_nested_marker_is_known(self):
        rc = make_plan(
            [change("a.b", "aws_x", ["create"], after={}, after_unknown={"tags": {}})]
        ).resource_changes[0]
        assert not rc.is_unknown("tags")

    def test_an_absent_key_is_known(self):
        rc = make_plan([change("a.b", "aws_x", ["update"], after={})]).resource_changes[0]
        assert not rc.is_unknown("anything")

    def test_sensitive_false_does_not_raise(self):
        # Terraform emits `false`, not `{}`, when nothing is sensitive.
        rc = make_plan(
            [change("a.b", "aws_x", ["update"], before={}, after={}, after_sensitive=False)]
        ).resource_changes[0]
        assert rc.is_sensitive("anything") is False

    def test_sensitive_is_detected_from_either_side(self):
        rc = make_plan(
            [
                change(
                    "a.b",
                    "aws_x",
                    ["update"],
                    before={"k": "old"},
                    after={"k": "new"},
                    before_sensitive={"k": True},
                )
            ]
        ).resource_changes[0]
        assert rc.is_sensitive("k")

    def test_an_unknown_attribute_counts_as_changed(self):
        rc = make_plan(
            [change("a.b", "aws_x", ["update"], before={"p": "x"}, after={}, after_unknown={"p": True})]
        ).resource_changes[0]
        assert rc.changed("p")


class TestPlanShape:
    def test_null_before_on_create_becomes_an_empty_dict(self):
        rc = make_plan([change("a.b", "aws_x", ["create"], before=None, after={"k": 1})]).resource_changes[0]
        assert rc.before == {}
        assert rc.value("k") == 1

    def test_drift_is_parsed_when_present(self):
        plan = make_plan(
            [change("a.b", "aws_x", ["update"])],
            drift=[change("a.c", "aws_security_group", ["update"])],
        )
        assert [rc.address for rc in plan.drift] == ["a.c"]

    def test_drift_is_empty_when_absent(self):
        assert make_plan([change("a.b", "aws_x", ["update"])]).drift == []

    def test_modules_and_providers_are_listed(self):
        plan = make_plan(
            [change("module.net.aws_x.y", "aws_x", ["update"], module_address="module.net")]
        )
        assert plan.modules() == ["module.net"]
        assert plan.providers() == ["registry.terraform.io/hashicorp/aws"]

    def test_of_type_filters(self):
        plan = make_plan(
            [
                change("a.b", "aws_security_group", ["update"]),
                change("a.c", "aws_instance", ["update"]),
            ]
        )
        assert [rc.address for rc in plan.of_type("aws_security_group")] == ["a.b"]

    def test_replace_paths_are_tuples(self):
        rc = make_plan(
            [change("a.b", "aws_x", ["delete", "create"], replace_paths=[["name"]])]
        ).resource_changes[0]
        assert rc.replace_paths == (("name",),)

    def test_digest_is_recorded_for_attestation(self):
        plan = make_plan([change("a.b", "aws_x", ["update"])])
        assert len(plan.digest) == 64
