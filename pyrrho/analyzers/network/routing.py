"""Routing and segmentation: reachability that no security group mentions.

A subnet becomes reachable when its route table gains a way out, or when the
subnet is pointed at a different table. No security group changes, no public IP
attribute flips, and every instance in it is now on the internet. Peering and
transit gateway attachments are the same shape one level up: they remove the
boundary that limits how far an intrusion travels.
"""

from __future__ import annotations

from typing import Any

from ... import cidr
from ...core import Finding, Severity
from ...plan import Plan, ResourceChange
from .shared import _reaches_internet


class RoutingChecks:
    """Mixed into the NetworkExposure analyzer; see network_exposure.py."""

    def _index_route_tables(self, plan: Plan) -> dict[str, dict[str, Any]]:
        """Route tables in the plan, and whether each reaches the internet."""
        index: dict[str, dict[str, Any]] = {}
        for rc in plan.resource_changes:
            if rc.type not in ("aws_route_table", "aws_default_route_table"):
                continue
            routes = rc.value("route") or rc.prior("route") or []
            gateways = [
                r.get("gateway_id")
                for r in routes
                if isinstance(r, dict) and _reaches_internet(r)
            ]
            entry = {"public": bool(gateways), "gateways": [g for g in gateways if g]}
            for key in (rc.value("id"), rc.prior("id"), rc.address):
                if isinstance(key, str) and key:
                    index[key] = entry
        return index
    def _routing(self, rc: ResourceChange) -> list[Finding]:
        """A subnet becomes reachable when its route table gains a way out.

        No security group changes, no public IP attribute flips, and the subnet
        is now on the internet. This is the step that actually makes an address
        reachable, and it is the one most reviews never look at.
        """
        if rc.type in ("aws_route", "aws_route_table", "aws_default_route_table"):
            return self._internet_route(rc)
        if rc.type == "aws_route_table_association":
            return self._subnet_association(rc)
        return []
    def _internet_route(self, rc: ResourceChange) -> list[Finding]:
        if rc.type == "aws_route":
            new_routes = [rc.after] if _reaches_internet(rc.after) else []
            old_routes = [rc.before] if _reaches_internet(rc.before) else []
        else:
            after = rc.value("route") or []
            before = rc.prior("route") or []
            new_routes = [r for r in after if isinstance(r, dict) and _reaches_internet(r)]
            old_routes = [r for r in before if isinstance(r, dict) and _reaches_internet(r)]

        if not new_routes:
            return []
        old_targets = {r.get("gateway_id") for r in old_routes}
        genuinely_new = [r for r in new_routes if r.get("gateway_id") not in old_targets]
        if not genuinely_new:
            return []

        return [
            self.finding(
                "NE013",
                "Default route to an internet gateway added",
                Severity.HIGH,
                rc.address,
                "This route table now sends unmatched traffic to an internet gateway. Every "
                "subnet associated with it becomes publicly routable, which no security "
                "group change is needed to bring about and no end-state policy check reads "
                "as an exposure.",
                evidence={
                    "routes_added": [
                        {
                            "destination": r.get("destination_cidr_block")
                            or r.get("destination_ipv6_cidr_block"),
                            "gateway_id": r.get("gateway_id"),
                        }
                        for r in genuinely_new
                    ],
                    "previously_routed_via": sorted(t for t in old_targets if t),
                },
                remediation=(
                    "Private subnets should route outbound traffic through a NAT gateway and "
                    "have no internet gateway route at all. Confirm which subnets this table "
                    "is associated with before approving."
                ),
            )
        ]
    def _subnet_association(self, rc: ResourceChange) -> list[Finding]:
        table = rc.value("route_table_id")
        was = rc.prior("route_table_id")
        if not isinstance(table, str) or table == was:
            return []
        entry = self._routes.get(table)
        if not entry or not entry["public"]:
            return []

        return [
            self.finding(
                "NE013",
                "Subnet moved onto a route table that reaches the internet",
                Severity.HIGH,
                rc.address,
                f"The subnet is being associated with {table}, which has a route to an "
                f"internet gateway. Nothing about the subnet or its security groups changes; "
                f"its reachability does.",
                evidence={
                    "route_table": {"before": was, "after": table},
                    "subnet_id": rc.value("subnet_id"),
                    "internet_gateways": entry["gateways"],
                },
                remediation=(
                    "Associate workload subnets with a private route table. If public "
                    "reachability is intended, say so in the change description."
                ),
            )
        ]
    def _segment_join(self, rc: ResourceChange) -> list[Finding]:
        peering_types = {
            "aws_vpc_peering_connection": "VPC peering connection",
            "aws_vpc_peering_connection_accepter": "VPC peering acceptance",
            "aws_ec2_transit_gateway_vpc_attachment": "transit gateway attachment",
            "aws_vpn_connection": "VPN connection",
            "aws_dx_gateway_association": "Direct Connect gateway association",
        }

        if rc.type in peering_types and rc.is_create:
            what = peering_types[rc.type]
            return [
                self.finding(
                    "NE015",
                    "Two network segments are being joined",
                    Severity.MEDIUM,
                    rc.address,
                    f"This plan creates a {what}. Segmentation is the control that limits how "
                    f"far an intrusion travels, and joining two segments removes it for every "
                    f"workload on both sides, not only the one this change is about.",
                    evidence={
                        "resource_type": rc.type,
                        "peer_vpc_id": rc.value("peer_vpc_id"),
                        "vpc_id": rc.value("vpc_id"),
                        "transit_gateway_id": rc.value("transit_gateway_id"),
                        "peer_owner_id": rc.value("peer_owner_id"),
                        "auto_accept": rc.value("auto_accept"),
                    },
                    remediation=(
                        "Confirm both sides agreed to this. Then keep the routes as specific "
                        "as the traffic requires: a peering connection with a /16 route is a "
                        "flat network with extra steps."
                    ),
                )
            ]

        # A route across an existing peering or transit gateway is the moment
        # the two segments actually start talking.
        if rc.type == "aws_route" and rc.is_create:
            for attribute, label in (
                ("vpc_peering_connection_id", "VPC peering connection"),
                ("transit_gateway_id", "transit gateway"),
            ):
                target = rc.value(attribute)
                if not target:
                    continue
                destination = rc.value("destination_cidr_block") or rc.value(
                    "destination_ipv6_cidr_block"
                )
                nets = cidr.parse_all([destination] if isinstance(destination, str) else [])
                wide = any(n.prefixlen <= 16 for n in nets)
                return [
                    self.finding(
                        "NE015",
                        "Route added across a link between segments",
                        Severity.HIGH if wide else Severity.MEDIUM,
                        rc.address,
                        f"Traffic for {destination} is being routed over a {label}. "
                        + (
                            "The destination is wide enough to cover the peer's whole network, "
                            "so this is a flat network between the two."
                            if wide
                            else "Confirm the destination is only the specific service that "
                            "needs to be reachable."
                        ),
                        evidence={
                            "destination": destination,
                            attribute: target,
                            "route_table_id": rc.value("route_table_id"),
                        },
                        remediation=(
                            "Route only the specific prefixes the integration needs, and pair "
                            "the route with security groups on the peer side."
                        ),
                    )
                ]
        return []
