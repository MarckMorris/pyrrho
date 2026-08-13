"""Tests for the rules that reason about more than one resource at a time.

Routing, security-group references, segment joins, shared prefix lists and
resource policies. What these have in common is that the dangerous change is not
visible in the resource the diff draws your eye to.
"""

from __future__ import annotations

import json

from pyrrho.analyzers.network_exposure import NetworkExposure
from pyrrho.core import Severity

from .conftest import change, group, make_plan, rule, rule_ids


def run(changes):
    return NetworkExposure().run(make_plan(changes))


IGW = "igw-0abc123456789def0"


def route(**attrs):
    return {"route_table_id": "rtb-0private00000000", **attrs}


class TestInternetRoutes:
    def test_a_default_route_to_an_internet_gateway_is_reported(self):
        findings = run(
            [
                change(
                    "aws_route.egress",
                    "aws_route",
                    ["create"],
                    after=route(destination_cidr_block="0.0.0.0/0", gateway_id=IGW),
                )
            ]
        )
        assert rule_ids(findings) == {"NE013"}
        assert findings[0].severity is Severity.HIGH

    def test_a_default_route_to_a_nat_gateway_is_not_reported(self):
        """A private subnet reaching out is the normal case.

        A rule keyed on 0.0.0.0/0 alone would report this; the target is what
        decides whether anything can reach *in*.
        """
        findings = run(
            [
                change(
                    "aws_route.egress",
                    "aws_route",
                    ["create"],
                    after=route(destination_cidr_block="0.0.0.0/0", nat_gateway_id="nat-0abc"),
                )
            ]
        )
        assert findings == []

    def test_a_specific_route_through_an_internet_gateway_is_not_a_default_route(self):
        findings = run(
            [
                change(
                    "aws_route.specific",
                    "aws_route",
                    ["create"],
                    after=route(destination_cidr_block="52.94.0.0/16", gateway_id=IGW),
                )
            ]
        )
        assert findings == []

    def test_an_inline_route_block_on_a_route_table_is_read(self):
        findings = run(
            [
                change(
                    "aws_route_table.private",
                    "aws_route_table",
                    ["update"],
                    before={"route": []},
                    after={"route": [{"destination_cidr_block": "0.0.0.0/0", "gateway_id": IGW}]},
                )
            ]
        )
        assert rule_ids(findings) == {"NE013"}

    def test_a_route_that_was_already_there_is_not_re_reported(self):
        existing = [{"destination_cidr_block": "0.0.0.0/0", "gateway_id": IGW}]
        findings = run(
            [
                change(
                    "aws_route_table.public",
                    "aws_route_table",
                    ["update"],
                    before={"route": existing, "tags": {}},
                    after={"route": existing, "tags": {"Name": "public"}},
                )
            ]
        )
        assert findings == []

    def test_an_ipv6_egress_only_gateway_route_is_reported(self):
        findings = run(
            [
                change(
                    "aws_route.v6",
                    "aws_route",
                    ["create"],
                    after=route(destination_ipv6_cidr_block="::/0", egress_only_gateway_id="eigw-0abc"),
                )
            ]
        )
        assert rule_ids(findings) == {"NE013"}


class TestSubnetAssociation:
    def public_table(self):
        return change(
            "aws_route_table.public",
            "aws_route_table",
            ["no-op"],
            before={"id": "rtb-0public", "route": [{"destination_cidr_block": "0.0.0.0/0", "gateway_id": IGW}]},
            after={"id": "rtb-0public", "route": [{"destination_cidr_block": "0.0.0.0/0", "gateway_id": IGW}]},
        )

    def private_table(self):
        return change(
            "aws_route_table.private",
            "aws_route_table",
            ["no-op"],
            before={"id": "rtb-0private", "route": [{"destination_cidr_block": "0.0.0.0/0", "nat_gateway_id": "nat-0a"}]},
            after={"id": "rtb-0private", "route": [{"destination_cidr_block": "0.0.0.0/0", "nat_gateway_id": "nat-0a"}]},
        )

    def association(self, before_table, after_table):
        return change(
            "aws_route_table_association.app",
            "aws_route_table_association",
            ["update"],
            before={"subnet_id": "subnet-0app", "route_table_id": before_table},
            after={"subnet_id": "subnet-0app", "route_table_id": after_table},
        )

    def test_moving_a_subnet_onto_a_public_table_is_reported(self):
        findings = run([self.public_table(), self.association("rtb-0private", "rtb-0public")])
        assert rule_ids(findings) == {"NE013"}
        assert findings[0].evidence["internet_gateways"] == [IGW]

    def test_moving_a_subnet_onto_a_private_table_is_not_reported(self):
        findings = run([self.private_table(), self.association("rtb-0public", "rtb-0private")])
        assert findings == []

    def test_an_unchanged_association_is_not_reported(self):
        findings = run([self.public_table(), self.association("rtb-0public", "rtb-0public")])
        assert findings == []

    def test_a_table_not_in_the_plan_cannot_be_judged(self):
        findings = run([self.association("rtb-0private", "rtb-0unknown")])
        assert findings == []


class TestSecurityGroupReferences:
    def open_group(self, ports_rule=None):
        rules = [ports_rule or rule(0, 65535, "tcp", ["0.0.0.0/0"], "public tier")]
        return change(
            "aws_security_group.web",
            "aws_security_group",
            ["no-op"],
            before={**group("web", rules), "id": "sg-0web"},
            after={**group("web", rules), "id": "sg-0web"},
        )

    def closed_group(self):
        rules = [rule(443, 443, "tcp", ["10.0.0.0/8"], "internal")]
        return change(
            "aws_security_group.internal",
            "aws_security_group",
            ["no-op"],
            before={**group("internal", rules), "id": "sg-0int"},
            after={**group("internal", rules), "id": "sg-0int"},
        )

    def referencing_rule(self, source):
        return change(
            "aws_security_group_rule.db",
            "aws_security_group_rule",
            ["create"],
            after={
                "type": "ingress",
                "security_group_id": "sg-0db",
                "source_security_group_id": source,
                "from_port": 5432,
                "to_port": 5432,
                "protocol": "tcp",
                "cidr_blocks": [],
            },
        )

    def test_a_reference_to_an_open_group_is_reported(self):
        findings = run([self.open_group(), self.referencing_rule("sg-0web")])
        assert rule_ids(findings) == {"NE014"}
        assert findings[0].severity is Severity.HIGH
        assert findings[0].evidence["resolved"] is True

    def test_a_reference_to_a_closed_group_is_not_reported(self):
        findings = run([self.closed_group(), self.referencing_rule("sg-0int")])
        assert findings == []

    def test_a_reference_that_cannot_be_resolved_says_so_rather_than_passing_over(self):
        findings = run([self.referencing_rule("sg-0elsewhere")])
        assert rule_ids(findings) == {"NE014"}
        assert findings[0].severity is Severity.LOW
        assert findings[0].evidence["resolved"] is False

    def test_a_non_admin_port_behind_an_open_group_is_medium(self):
        referencing = change(
            "aws_security_group_rule.app",
            "aws_security_group_rule",
            ["create"],
            after={
                "type": "ingress",
                "source_security_group_id": "sg-0web",
                "from_port": 9000,
                "to_port": 9000,
                "protocol": "tcp",
            },
        )
        findings = run([self.open_group(), referencing])
        assert findings[0].severity is Severity.MEDIUM

    def test_a_reference_that_was_already_there_is_not_re_reported(self):
        existing = {
            "type": "ingress",
            "source_security_group_id": "sg-0web",
            "from_port": 5432,
            "to_port": 5432,
            "protocol": "tcp",
        }
        referencing = change(
            "aws_security_group_rule.db",
            "aws_security_group_rule",
            ["update"],
            before=existing,
            after=dict(existing, description="tidy up"),
        )
        assert run([self.open_group(), referencing]) == []

    def test_the_modern_rule_resource_reference_attribute_is_read(self):
        referencing = change(
            "aws_vpc_security_group_ingress_rule.db",
            "aws_vpc_security_group_ingress_rule",
            ["create"],
            after={
                "referenced_security_group_id": "sg-0web",
                "from_port": 5432,
                "to_port": 5432,
                "ip_protocol": "tcp",
            },
        )
        assert rule_ids(run([self.open_group(), referencing])) == {"NE014"}


class TestSegmentJoins:
    def test_a_new_peering_connection_is_reported(self):
        findings = run(
            [
                change(
                    "aws_vpc_peering_connection.p",
                    "aws_vpc_peering_connection",
                    ["create"],
                    after={"vpc_id": "vpc-a", "peer_vpc_id": "vpc-b", "auto_accept": True},
                )
            ]
        )
        assert rule_ids(findings) == {"NE015"}
        assert findings[0].severity is Severity.MEDIUM

    def test_a_transit_gateway_attachment_is_reported(self):
        findings = run(
            [
                change(
                    "aws_ec2_transit_gateway_vpc_attachment.a",
                    "aws_ec2_transit_gateway_vpc_attachment",
                    ["create"],
                    after={"transit_gateway_id": "tgw-0a", "vpc_id": "vpc-a"},
                )
            ]
        )
        assert rule_ids(findings) == {"NE015"}

    def test_a_wide_route_across_a_peering_is_high(self):
        findings = run(
            [
                change(
                    "aws_route.peer",
                    "aws_route",
                    ["create"],
                    after=route(destination_cidr_block="10.50.0.0/16", vpc_peering_connection_id="pcx-0a"),
                )
            ]
        )
        assert findings[0].rule_id == "NE015"
        assert findings[0].severity is Severity.HIGH

    def test_a_narrow_route_across_a_peering_is_medium(self):
        findings = run(
            [
                change(
                    "aws_route.peer",
                    "aws_route",
                    ["create"],
                    after=route(destination_cidr_block="10.50.7.12/32", vpc_peering_connection_id="pcx-0a"),
                )
            ]
        )
        assert findings[0].severity is Severity.MEDIUM

    def test_deleting_a_peering_connection_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_vpc_peering_connection.p",
                    "aws_vpc_peering_connection",
                    ["delete"],
                    before={"vpc_id": "vpc-a", "peer_vpc_id": "vpc-b"},
                    after=None,
                )
            ]
        )
        assert findings == []


class TestResourcePolicies:
    def bucket_policy(self, statements, before=None):
        document = json.dumps({"Version": "2012-10-17", "Statement": statements})
        return change(
            "aws_s3_bucket_policy.assets",
            "aws_s3_bucket_policy",
            ["update"] if before else ["create"],
            before={"bucket": "b", "policy": json.dumps({"Statement": before})} if before else None,
            after={"bucket": "b", "policy": document},
        )

    PUBLIC = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
    NAMED = {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111122223333:role/app"},
        "Action": "s3:GetObject",
        "Resource": "*",
    }

    def test_a_wildcard_principal_is_critical(self):
        findings = run([self.bucket_policy([self.PUBLIC])])
        assert rule_ids(findings) == {"NE017"}
        assert findings[0].severity is Severity.CRITICAL

    def test_a_named_principal_is_not_reported(self):
        assert run([self.bucket_policy([self.NAMED])]) == []

    def test_a_wildcard_with_a_condition_is_not_reported(self):
        conditioned = dict(self.PUBLIC, Condition={"StringEquals": {"aws:SourceVpce": "vpce-0a"}})
        assert run([self.bucket_policy([conditioned])]) == []

    def test_a_wildcard_that_was_already_there_is_not_re_reported(self):
        assert run([self.bucket_policy([self.PUBLIC], before=[self.PUBLIC])]) == []

    def test_a_deny_to_everyone_is_not_a_grant(self):
        deny = dict(self.PUBLIC, Effect="Deny")
        assert run([self.bucket_policy([deny])]) == []

    def test_an_unparseable_policy_does_not_crash(self):
        broken = change(
            "aws_s3_bucket_policy.assets",
            "aws_s3_bucket_policy",
            ["create"],
            after={"bucket": "b", "policy": "{not json"},
        )
        assert run([broken]) == []

    def test_an_sqs_queue_policy_is_covered_too(self):
        findings = run(
            [
                change(
                    "aws_sqs_queue_policy.q",
                    "aws_sqs_queue_policy",
                    ["create"],
                    after={"policy": json.dumps({"Statement": [self.PUBLIC]})},
                )
            ]
        )
        assert rule_ids(findings) == {"NE017"}
        assert "SQS queue" in findings[0].title


class TestPrefixLists:
    def prefix_list(self, before_entries, after_entries):
        return change(
            "aws_ec2_managed_prefix_list.corporate",
            "aws_ec2_managed_prefix_list",
            ["update"] if before_entries is not None else ["create"],
            before={"name": "corporate", "entry": before_entries} if before_entries is not None else None,
            after={"name": "corporate", "entry": after_entries},
        )

    def test_adding_the_whole_internet_is_critical(self):
        findings = run([self.prefix_list([{"cidr": "203.0.113.0/24"}], [{"cidr": "203.0.113.0/24"}, {"cidr": "0.0.0.0/0"}])])
        assert rule_ids(findings) == {"NE018"}
        assert findings[0].severity is Severity.CRITICAL

    def test_adding_a_broad_public_block_is_high(self):
        findings = run([self.prefix_list([{"cidr": "45.33.32.0/24"}], [{"cidr": "45.0.0.0/8"}])])
        assert findings[0].severity is Severity.HIGH

    def test_adding_a_specific_range_is_not_reported(self):
        findings = run([self.prefix_list([{"cidr": "45.33.32.0/24"}], [{"cidr": "45.33.32.0/24"}, {"cidr": "45.33.64.0/24"}])])
        assert findings == []

    def test_removing_an_entry_is_not_reported(self):
        findings = run([self.prefix_list([{"cidr": "0.0.0.0/0"}], [{"cidr": "45.33.32.0/24"}])])
        assert findings == []

    def test_a_malformed_entry_does_not_crash(self):
        assert run([self.prefix_list([], [{"description": "no cidr here"}])]) == []


class TestNetworkAclDelta:
    def acl_rule(self, action, cidr_block, actions, number=100):
        attrs = {
            "network_acl_id": "acl-0a",
            "rule_number": number,
            "egress": False,
            "protocol": "-1",
            "rule_action": action,
            "cidr_block": cidr_block,
        }
        return change(
            "aws_network_acl_rule.r",
            "aws_network_acl_rule",
            actions,
            before=attrs if actions != ["create"] else None,
            after=attrs if actions != ["delete"] else None,
        )

    def test_deleting_a_deny_entry_is_reported(self):
        findings = run([self.acl_rule("deny", "10.90.0.0/16", ["delete"])])
        assert rule_ids(findings) == {"NE016"}
        assert findings[0].severity is Severity.HIGH
        assert findings[0].evidence["removed_or_replaced"] == "removed"

    def test_flipping_a_deny_to_an_allow_is_reported_twice_over(self):
        flipped = change(
            "aws_network_acl_rule.r",
            "aws_network_acl_rule",
            ["update"],
            before={"network_acl_id": "acl-0a", "rule_number": 100, "rule_action": "deny", "cidr_block": "0.0.0.0/0", "protocol": "-1"},
            after={"network_acl_id": "acl-0a", "rule_number": 100, "rule_action": "allow", "cidr_block": "0.0.0.0/0", "protocol": "-1"},
        )
        findings = run([flipped])
        assert rule_ids(findings) == {"NE008", "NE016"}

    def test_deleting_an_allow_entry_is_not_reported(self):
        assert run([self.acl_rule("allow", "0.0.0.0/0", ["delete"])]) == []

    def test_an_allow_that_was_already_there_is_not_re_reported(self):
        unchanged = {
            "network_acl_id": "acl-0a",
            "rule_number": 100,
            "rule_action": "allow",
            "cidr_block": "0.0.0.0/0",
            "protocol": "-1",
        }
        findings = run(
            [
                change(
                    "aws_network_acl_rule.r",
                    "aws_network_acl_rule",
                    ["update"],
                    before=unchanged,
                    after=dict(unchanged, protocol="tcp"),
                )
            ]
        )
        assert findings == []

    def test_a_default_network_acl_is_covered(self):
        findings = run(
            [
                change(
                    "aws_default_network_acl.d",
                    "aws_default_network_acl",
                    ["update"],
                    before={"ingress": []},
                    after={"ingress": [{"rule_no": 100, "action": "allow", "cidr_block": "0.0.0.0/0", "protocol": "-1"}]},
                )
            ]
        )
        assert rule_ids(findings) == {"NE008"}


class TestProtocolSpellings:
    def test_a_numeric_protocol_is_the_same_as_its_name(self):
        by_number = run(
            [
                change(
                    "aws_security_group.web",
                    "aws_security_group",
                    ["create"],
                    after=group("web", [rule(22, 22, "6", ["0.0.0.0/0"])]),
                )
            ]
        )
        assert rule_ids(by_number) == {"NE001"}

    def test_the_protocol_number_does_not_break_pairing_with_the_prior_rule(self):
        findings = run(
            [
                change(
                    "aws_security_group.web",
                    "aws_security_group",
                    ["update"],
                    before=group("web", [rule(22, 22, "tcp", ["0.0.0.0/0"])]),
                    after=group("web", [rule(22, 22, "6", ["0.0.0.0/0"])]),
                )
            ]
        )
        assert findings == []
