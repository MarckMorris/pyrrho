"""Network exposure analyzer: what this plan makes reachable that was not.

The discipline here is delta-only. A security group that already allowed SSH
from __future__ import annotations

from the world before this plan ran is a real problem, but it is not *this pull
request's* problem, and reporting it as such is how scanners train people to
ignore them. Every check compares the planned state against the prior state and
reports the difference.

The one deliberate exception is a resource being created: everything it opens is
new by definition, so all of it is in the delta.

The checks themselves live in the ``network`` package, one module per question:

    security_groups   what a rule newly admits, and from where
    routing           reachability no security group mentions
    services          managed services that go public by attribute
    policies          guards removed, resource policies, prefix lists, ACLs

They are mixed in rather than called as functions so that each keeps direct
access to ``self.finding`` and to the two cross-resource indexes ``run`` builds.
"""

from typing import Any

from ..core import Analyzer, Finding, register
from ..plan import Plan
from .network import (
    PolicyChecks,
    RoutingChecks,
    SecurityGroupChecks,
    ServiceExposureChecks,
)
from .network.shared import (  # re-exported: tests and tooling import these here
    DEFAULT_SG,
    INLINE_SG,
    INLINE_SG_TYPES,
    NETWORK_ACL_TYPES,
    PUBLICLY_ACCESSIBLE_TYPES,
    PUBLIC_ACCESS_BLOCK_TYPES,
    RESOURCE_POLICY_TYPES,
    SGRule,
    STANDALONE_SG_RULE,
    UNRESOLVABLE_RULE_ATTRIBUTES,
    VPC_EGRESS_RULE,
    VPC_INGRESS_RULE,
    extract_rules,
)

__all__ = [
    "NetworkExposure",
    "SGRule",
    "extract_rules",
    "INLINE_SG",
    "DEFAULT_SG",
    "INLINE_SG_TYPES",
    "STANDALONE_SG_RULE",
    "VPC_INGRESS_RULE",
    "VPC_EGRESS_RULE",
    "NETWORK_ACL_TYPES",
    "PUBLIC_ACCESS_BLOCK_TYPES",
    "PUBLICLY_ACCESSIBLE_TYPES",
    "RESOURCE_POLICY_TYPES",
    "UNRESOLVABLE_RULE_ATTRIBUTES",
]


@register

class NetworkExposure(
    SecurityGroupChecks,
    RoutingChecks,
    ServiceExposureChecks,
    PolicyChecks,
    Analyzer,
):
    """Reports what the plan newly exposes to networks it was not exposed to."""

    name = "network-exposure"
    description = (
        "Finds security group openings, lost segmentation, routing changes and "
        "resources becoming publicly reachable, comparing planned state against "
        "prior state."
    )

    SG_TYPES = (*INLINE_SG_TYPES, STANDALONE_SG_RULE, VPC_INGRESS_RULE, VPC_EGRESS_RULE)

    def __init__(self) -> None:
        # Populated by run(); declared here so a method called in isolation by a
        # test gets an empty index rather than an AttributeError.
        self._groups: dict[str, list[SGRule]] = {}
        self._routes: dict[str, dict[str, Any]] = {}

    def run(self, plan: Plan) -> list[Finding]:
        # Some questions cannot be answered from one resource. "Is this rule
        # sourced from a group that is itself open?" needs every group in the
        # plan; "does this subnet now route to the internet?" needs the route
        # table the association points at.
        self._groups = self._index_security_groups(plan)
        self._routes = self._index_route_tables(plan)

        findings: list[Finding] = []
        for rc in plan.effective_changes:
            if rc.type in self.SG_TYPES:
                findings.extend(self._security_group(rc))
            findings.extend(self._public_access_block(rc))
            findings.extend(self._rds(rc))
            findings.extend(self._load_balancer(rc))
            findings.extend(self._network_acl(rc))
            findings.extend(self._kubernetes(rc))
            findings.extend(self._public_ip(rc))
            findings.extend(self._routing(rc))
            findings.extend(self._segment_join(rc))
            findings.extend(self._resource_policy(rc))
            findings.extend(self._prefix_list(rc))
        return findings
