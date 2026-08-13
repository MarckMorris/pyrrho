"""Tests for the network exposure analyzer.

The delta discipline gets the most attention here, because it is the property
that decides whether the tool is usable on an estate that already has problems.
"""

from __future__ import annotations

from pyrrho.analyzers.network_exposure import NetworkExposure
from pyrrho import cidr
from pyrrho.core import Severity

from .conftest import change, group, make_plan, rule, rule_ids


def run(changes, drift=None):
    return NetworkExposure().run(make_plan(changes, drift))


def sg_change(before_rules, after_rules, actions=("update",), address="aws_security_group.web"):
    return change(
        address,
        "aws_security_group",
        list(actions),
        before=group("web", before_rules) if before_rules is not None else None,
        after=group("web", after_rules),
    )


class TestWorldExposure:
    def test_ssh_opened_to_the_world_is_critical(self):
        findings = run([sg_change([rule(22, 22, "tcp", ["203.0.113.0/24"])], [rule(22, 22, "tcp", ["0.0.0.0/0"])])])
        assert rule_ids(findings) == {"NE001"}
        assert findings[0].severity is Severity.CRITICAL
        assert "SSH" in findings[0].detail

    def test_all_ports_to_the_world_is_its_own_rule(self):
        findings = run([sg_change(None, [rule(0, 0, "-1", ["0.0.0.0/0"])], actions=["create"])])
        assert "NE002" in rule_ids(findings)
        assert "NE001" not in rule_ids(findings)

    def test_https_to_the_world_is_only_a_note(self):
        findings = run([sg_change(None, [rule(443, 443, "tcp", ["0.0.0.0/0"])], actions=["create"])])
        assert rule_ids(findings) == {"NE003"}
        assert findings[0].severity is Severity.LOW

    def test_an_unusual_port_to_the_world_is_high(self):
        findings = run([sg_change(None, [rule(8080, 8080, "tcp", ["0.0.0.0/0"])], actions=["create"])])
        assert findings[0].rule_id == "NE003"
        assert findings[0].severity is Severity.HIGH

    def test_ipv6_default_route_is_caught(self):
        after = rule(22, 22, "tcp", [])
        after["ipv6_cidr_blocks"] = ["::/0"]
        findings = run([sg_change([], [after])])
        assert "NE001" in rule_ids(findings)

    def test_a_wide_port_range_reports_every_service_it_swallows(self):
        findings = run([sg_change(None, [rule(1024, 65535, "tcp", ["0.0.0.0/0"])], actions=["create"])])
        exposed = findings[0].evidence["services_exposed"]
        assert "6379" in exposed and "27017" in exposed


class TestDeltaDiscipline:
    def test_preexisting_exposure_is_not_reported(self):
        """The single most important test in this file."""
        existing = [rule(22, 22, "tcp", ["0.0.0.0/0"])]
        findings = run([sg_change(existing, list(existing))])
        assert findings == []

    def test_narrowing_a_rule_is_not_reported(self):
        findings = run([sg_change([rule(22, 22, "tcp", ["0.0.0.0/0"])], [rule(22, 22, "tcp", ["10.20.0.0/16"])])])
        assert findings == []

    def test_adding_a_subnet_of_an_existing_allowance_is_not_reported(self):
        findings = run([sg_change([rule(443, 443, "tcp", ["10.0.0.0/8"])], [rule(443, 443, "tcp", ["10.1.0.0/16"])])])
        assert findings == []

    def test_a_creation_reports_everything_it_opens(self):
        findings = run([sg_change(None, [rule(22, 22, "tcp", ["0.0.0.0/0"])], actions=["create"])])
        assert "NE001" in rule_ids(findings)

    def test_widening_within_a_different_port_is_judged_separately(self):
        before = [rule(443, 443, "tcp", ["0.0.0.0/0"])]
        after = [rule(443, 443, "tcp", ["0.0.0.0/0"]), rule(22, 22, "tcp", ["0.0.0.0/0"])]
        findings = run([sg_change(before, after)])
        assert rule_ids(findings) == {"NE001"}


def widened_db_rule(before_cidrs, after_cidrs, port=3306):
    return change(
        "aws_security_group_rule.db",
        "aws_security_group_rule",
        ["update"],
        before={"type": "ingress", "from_port": port, "to_port": port, "protocol": "tcp", "cidr_blocks": before_cidrs},
        after={"type": "ingress", "from_port": port, "to_port": port, "protocol": "tcp", "cidr_blocks": after_cidrs},
    )


class TestWidening:
    def test_widening_to_a_public_slash_8_on_a_database_port(self):
        """The exposure is the finding; the widening is evidence for it.

        Reporting NE001 *and* NE004 here would be two alerts for one problem,
        and the second always reads as the first restated.
        """
        findings = run([widened_db_rule(["198.51.100.0/24"], ["198.0.0.0/8"])])
        assert rule_ids(findings) == {"NE001"}
        assert findings[0].severity is Severity.HIGH
        assert findings[0].evidence["reach"] == "broad"
        assert findings[0].evidence["widening_factor"] == 65536.0

    def test_a_widening_with_nothing_else_to_say_is_its_own_finding(self):
        # A public range that grew, on a port nothing well known listens on.
        findings = run([widened_db_rule(["45.33.32.0/24"], ["45.33.32.0/20"], port=8443)])
        assert rule_ids(findings) == {"NE004"}
        assert findings[0].severity is Severity.MEDIUM
        assert findings[0].evidence["widening_factor"] == 16.0

    def test_a_new_public_source_with_no_prior_cidr_is_not_dropped(self):
        """Regression: the widening branch required a prior CIDR to exist.

        A rule whose sources were security-group references only, gaining a
        hardcoded public /24 on MySQL, reported nothing at all. That is how a
        contractor gets database access.
        """
        findings = run([widened_db_rule([], ["45.33.32.0/24"])])
        assert rule_ids(findings) == {"NE001"}
        assert findings[0].severity is Severity.MEDIUM

    def test_a_brand_new_group_exposing_ssh_to_a_public_range_is_reported(self):
        findings = run([sg_change(None, [rule(22, 22, "tcp", ["45.33.32.0/24"])], actions=["create"])])
        assert rule_ids(findings) == {"NE001"}


class TestSplitInternet:
    """0.0.0.0/1 plus 128.0.0.0/1 is the whole internet, written as two CIDRs.

    Every `prefixlen == 0` check in the analyzer used to let this through. It is
    the cheapest evasion there is, because the rule reads as scoped in review.
    """

    HALVES = ["0.0.0.0/1", "128.0.0.0/1"]

    def test_all_ports_from_both_halves_is_still_critical(self):
        findings = run([sg_change(None, [rule(0, 0, "-1", self.HALVES)], actions=["create"])])
        assert rule_ids(findings) == {"NE002"}
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].evidence["reach"] == "internet"

    def test_ssh_from_both_halves_is_still_critical(self):
        findings = run([sg_change(None, [rule(22, 22, "tcp", self.HALVES)], actions=["create"])])
        assert rule_ids(findings) == {"NE001"}
        assert findings[0].severity is Severity.CRITICAL

    def test_an_unremarkable_port_from_both_halves_is_reported(self):
        findings = run([sg_change(None, [rule(8080, 8080, "tcp", self.HALVES)], actions=["create"])])
        assert rule_ids(findings) == {"NE003"}
        assert findings[0].severity is Severity.HIGH

    def test_egress_to_both_halves_is_reported(self):
        changed = change(
            "aws_security_group.worker",
            "aws_security_group",
            ["update"],
            before=group("worker", [], egress=[]),
            after=group("worker", [], egress=[rule(0, 0, "-1", self.HALVES)]),
        )
        assert rule_ids(run([changed])) == {"NE009"}

    def test_four_quarters_also_count(self):
        quarters = ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"]
        findings = run([sg_change(None, [rule(22, 22, "tcp", quarters)], actions=["create"])])
        assert findings[0].severity is Severity.CRITICAL

    def test_one_half_alone_is_not_the_whole_internet(self):
        findings = run([sg_change(None, [rule(22, 22, "tcp", ["0.0.0.0/1"])], actions=["create"])])
        assert findings[0].severity is Severity.HIGH  # broad, not internet-wide

    def test_ipv4_halves_do_not_imply_ipv6_coverage(self):
        assert cidr.reach(cidr.parse_all(["::/1"])) != "internet"


class TestRuleResourceShapes:
    def test_the_modern_singular_ingress_rule_is_understood(self):
        findings = run(
            [
                change(
                    "aws_vpc_security_group_ingress_rule.db",
                    "aws_vpc_security_group_ingress_rule",
                    ["create"],
                    after={"cidr_ipv4": "0.0.0.0/0", "from_port": 5432, "to_port": 5432, "ip_protocol": "tcp"},
                )
            ]
        )
        assert "NE001" in rule_ids(findings)
        assert "PostgreSQL" in findings[0].detail

    def test_the_legacy_standalone_rule_is_understood(self):
        findings = run(
            [
                change(
                    "aws_security_group_rule.ssh",
                    "aws_security_group_rule",
                    ["create"],
                    after={"type": "ingress", "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
                )
            ]
        )
        assert "NE001" in rule_ids(findings)

    def test_the_modern_egress_rule_is_understood(self):
        findings = run(
            [
                change(
                    "aws_vpc_security_group_egress_rule.out",
                    "aws_vpc_security_group_egress_rule",
                    ["create"],
                    after={"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1"},
                )
            ]
        )
        assert "NE009" in rule_ids(findings)


class TestEgress:
    def test_unrestricted_egress_is_medium_not_critical(self):
        findings = run([sg_change([], [], actions=["update"])])
        assert findings == []
        changed = change(
            "aws_security_group.worker",
            "aws_security_group",
            ["update"],
            before=group("worker", [], egress=[]),
            after=group("worker", [], egress=[rule(0, 0, "-1", ["0.0.0.0/0"])]),
        )
        findings = run([changed])
        assert rule_ids(findings) == {"NE009"}
        assert findings[0].severity is Severity.MEDIUM

    def test_scoped_egress_is_not_reported(self):
        changed = change(
            "aws_security_group.worker",
            "aws_security_group",
            ["update"],
            before=group("worker", [], egress=[]),
            after=group("worker", [], egress=[rule(443, 443, "tcp", ["10.0.0.0/8"])]),
        )
        assert run([changed]) == []


class TestUnknownRules:
    def test_unknown_ingress_is_reported_as_unreviewable(self):
        findings = run(
            [
                change(
                    "aws_security_group.dynamic",
                    "aws_security_group",
                    ["create"],
                    after={"name": "dynamic", "egress": []},
                    after_unknown={"ingress": True},
                )
            ]
        )
        assert rule_ids(findings) == {"NE012"}
        assert "cannot be reviewed" in findings[0].detail


class TestStorage:
    def test_disabling_a_public_access_guard_is_critical(self):
        findings = run(
            [
                change(
                    "aws_s3_bucket_public_access_block.assets",
                    "aws_s3_bucket_public_access_block",
                    ["update"],
                    before={"block_public_policy": True, "block_public_acls": True, "ignore_public_acls": True, "restrict_public_buckets": True},
                    after={"block_public_policy": False, "block_public_acls": True, "ignore_public_acls": True, "restrict_public_buckets": True},
                )
            ]
        )
        assert rule_ids(findings) == {"NE005"}
        assert findings[0].severity is Severity.CRITICAL

    def test_deleting_the_public_access_block_is_critical(self):
        findings = run(
            [
                change(
                    "aws_s3_bucket_public_access_block.assets",
                    "aws_s3_bucket_public_access_block",
                    ["delete"],
                    before={"block_public_policy": True},
                    after=None,
                )
            ]
        )
        assert rule_ids(findings) == {"NE005"}

    def test_creating_a_block_with_guards_already_off_is_reported(self):
        findings = run(
            [
                change(
                    "aws_s3_bucket_public_access_block.assets",
                    "aws_s3_bucket_public_access_block",
                    ["create"],
                    after={"block_public_policy": False, "block_public_acls": True, "ignore_public_acls": True, "restrict_public_buckets": True},
                )
            ]
        )
        assert rule_ids(findings) == {"NE005"}

    def test_creating_a_block_with_every_guard_on_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_s3_bucket_public_access_block.assets",
                    "aws_s3_bucket_public_access_block",
                    ["create"],
                    after={"block_public_policy": True, "block_public_acls": True, "ignore_public_acls": True, "restrict_public_buckets": True},
                )
            ]
        )
        assert findings == []

    def test_tightening_a_guard_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_s3_bucket_public_access_block.assets",
                    "aws_s3_bucket_public_access_block",
                    ["update"],
                    before={"block_public_policy": False, "block_public_acls": True, "ignore_public_acls": True, "restrict_public_buckets": True},
                    after={"block_public_policy": True, "block_public_acls": True, "ignore_public_acls": True, "restrict_public_buckets": True},
                )
            ]
        )
        assert findings == []


class TestDatabases:
    def test_making_a_database_public_is_critical(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"publicly_accessible": False},
                    after={"publicly_accessible": True},
                )
            ]
        )
        assert rule_ids(findings) == {"NE006"}

    def test_an_already_public_database_is_not_re_reported(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"publicly_accessible": True, "instance_class": "db.t3.small"},
                    after={"publicly_accessible": True, "instance_class": "db.t3.medium"},
                )
            ]
        )
        assert findings == []


class TestLoadBalancers:
    def test_internal_to_public_is_reported(self):
        findings = run(
            [change("aws_lb.api", "aws_lb", ["update"], before={"internal": True}, after={"internal": False})]
        )
        assert rule_ids(findings) == {"NE007"}

    def test_a_brand_new_public_load_balancer_is_not_reported(self):
        # Creating a public load balancer is usually the point of the change.
        findings = run([change("aws_lb.api", "aws_lb", ["create"], after={"internal": False})])
        assert findings == []

    def test_public_to_internal_is_not_reported(self):
        findings = run(
            [change("aws_lb.api", "aws_lb", ["update"], before={"internal": False}, after={"internal": True})]
        )
        assert findings == []


class TestSegmentation:
    def test_an_allow_all_nacl_entry_is_reported(self):
        findings = run(
            [
                change(
                    "aws_network_acl_rule.open",
                    "aws_network_acl_rule",
                    ["create"],
                    after={"rule_number": 100, "rule_action": "allow", "cidr_block": "0.0.0.0/0", "protocol": "-1"},
                )
            ]
        )
        assert rule_ids(findings) == {"NE008"}

    def test_a_deny_all_nacl_entry_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_network_acl_rule.blocked",
                    "aws_network_acl_rule",
                    ["create"],
                    after={"rule_number": 100, "rule_action": "deny", "cidr_block": "0.0.0.0/0", "protocol": "-1"},
                )
            ]
        )
        assert findings == []

    def test_inline_nacl_blocks_are_read(self):
        findings = run(
            [
                change(
                    "aws_network_acl.private",
                    "aws_network_acl",
                    ["create"],
                    after={
                        "ingress": [{"rule_no": 100, "action": "allow", "cidr_block": "0.0.0.0/0", "protocol": "-1"}],
                        "egress": [],
                    },
                )
            ]
        )
        assert rule_ids(findings) == {"NE008"}

    def test_a_launch_template_has_no_public_ip_attribute_to_check(self):
        findings = run(
            [change("aws_launch_template.workers", "aws_launch_template", ["create"], after={"image_id": "ami-1"})]
        )
        assert findings == []

    def test_a_scoped_nacl_entry_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_network_acl_rule.internal",
                    "aws_network_acl_rule",
                    ["create"],
                    after={"rule_number": 100, "rule_action": "allow", "cidr_block": "10.0.0.0/8", "protocol": "-1"},
                )
            ]
        )
        assert findings == []


class TestKubernetes:
    def test_a_public_api_server_with_no_allow_list_is_critical(self):
        findings = run(
            [
                change(
                    "aws_eks_cluster.platform",
                    "aws_eks_cluster",
                    ["update"],
                    before={"vpc_config": [{"endpoint_public_access": False, "public_access_cidrs": []}]},
                    after={"vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["0.0.0.0/0"]}]},
                )
            ]
        )
        assert rule_ids(findings) == {"NE010"}
        assert findings[0].severity is Severity.CRITICAL

    def test_a_public_api_server_with_an_allow_list_is_high(self):
        findings = run(
            [
                change(
                    "aws_eks_cluster.platform",
                    "aws_eks_cluster",
                    ["update"],
                    before={"vpc_config": [{"endpoint_public_access": False, "public_access_cidrs": []}]},
                    after={"vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["203.0.113.0/24"]}]},
                )
            ]
        )
        assert findings[0].severity is Severity.HIGH

    def test_an_already_public_cluster_whose_allow_list_opens_fully_is_reported(self):
        findings = run(
            [
                change(
                    "aws_eks_cluster.platform",
                    "aws_eks_cluster",
                    ["update"],
                    before={"vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["203.0.113.0/24"]}]},
                    after={"vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["0.0.0.0/0"]}]},
                )
            ]
        )
        assert rule_ids(findings) == {"NE010"}

    def test_an_already_public_cluster_with_a_stable_allow_list_is_not_re_reported(self):
        findings = run(
            [
                change(
                    "aws_eks_cluster.platform",
                    "aws_eks_cluster",
                    ["update"],
                    before={"vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["203.0.113.0/24"]}], "version": "1.29"},
                    after={"vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["203.0.113.0/24"]}], "version": "1.30"},
                )
            ]
        )
        assert findings == []

    def test_a_cluster_with_a_malformed_vpc_config_is_skipped(self):
        findings = run(
            [change("aws_eks_cluster.platform", "aws_eks_cluster", ["create"], after={"vpc_config": "unexpected"})]
        )
        assert findings == []

    def test_a_private_cluster_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_eks_cluster.platform",
                    "aws_eks_cluster",
                    ["create"],
                    after={"vpc_config": [{"endpoint_public_access": False, "endpoint_private_access": True}]},
                )
            ]
        )
        assert findings == []


class TestPublicAddresses:
    def test_a_subnet_switching_to_public_ips_is_reported(self):
        findings = run(
            [
                change(
                    "aws_subnet.app",
                    "aws_subnet",
                    ["update"],
                    before={"map_public_ip_on_launch": False},
                    after={"map_public_ip_on_launch": True},
                )
            ]
        )
        assert rule_ids(findings) == {"NE011"}

    def test_an_instance_keeping_its_public_ip_is_not_reported(self):
        findings = run(
            [
                change(
                    "aws_instance.web",
                    "aws_instance",
                    ["update"],
                    before={"associate_public_ip_address": True, "instance_type": "t3.small"},
                    after={"associate_public_ip_address": True, "instance_type": "t3.medium"},
                )
            ]
        )
        assert findings == []


class TestRobustness:
    def test_a_malformed_cidr_does_not_crash_the_review(self):
        findings = run([sg_change(None, [rule(22, 22, "tcp", ["not-a-cidr"])], actions=["create"])])
        assert findings == []

    def test_a_rule_with_no_sources_is_ignored(self):
        findings = run([sg_change(None, [rule(22, 22, "tcp", [])], actions=["create"])])
        assert findings == []

    def test_unrelated_resources_produce_nothing(self):
        findings = run([change("aws_iam_role.x", "aws_iam_role", ["update"], before={}, after={})])
        assert findings == []

    def test_a_non_numeric_port_does_not_crash(self):
        bad = rule("not-a-port", "also-not", "tcp", ["0.0.0.0/0"])
        findings = run([sg_change(None, [bad], actions=["create"])])
        assert "NE003" in rule_ids(findings)

    def test_a_string_where_a_cidr_list_belongs_is_accepted(self):
        # Some providers and some hand-written state carry a bare string here.
        findings = run(
            [
                change(
                    "aws_security_group_rule.ssh",
                    "aws_security_group_rule",
                    ["create"],
                    after={"type": "ingress", "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": "0.0.0.0/0"},
                )
            ]
        )
        assert "NE001" in rule_ids(findings)

    def test_a_non_list_ingress_block_is_ignored(self):
        findings = run(
            [
                change(
                    "aws_security_group.web",
                    "aws_security_group",
                    ["create"],
                    after={"name": "web", "ingress": "unexpected", "egress": []},
                )
            ]
        )
        assert findings == []

    def test_a_non_dict_ingress_entry_is_skipped(self):
        findings = run(
            [
                change(
                    "aws_security_group.web",
                    "aws_security_group",
                    ["create"],
                    after={"name": "web", "ingress": ["nonsense", rule(22, 22, "tcp", ["0.0.0.0/0"])], "egress": []},
                )
            ]
        )
        assert "NE001" in rule_ids(findings)

    def test_an_unrecognised_rule_direction_defaults_to_ingress(self):
        findings = run(
            [
                change(
                    "aws_security_group_rule.odd",
                    "aws_security_group_rule",
                    ["create"],
                    after={"type": "sideways", "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
                )
            ]
        )
        assert "NE001" in rule_ids(findings)

    def test_a_security_group_with_no_attributes_is_skipped(self):
        findings = run([change("aws_security_group.web", "aws_security_group", ["delete"], before={}, after=None)])
        assert findings == []

    def test_string_booleans_are_understood(self):
        findings = run(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["update"],
                    before={"publicly_accessible": "false"},
                    after={"publicly_accessible": "true"},
                )
            ]
        )
        assert rule_ids(findings) == {"NE006"}
