"""Managed services that become publicly reachable by attribute.

One boolean on a database, a load balancer, a Kubernetes control plane or a
launch template, and the resource has a public endpoint. `publicly_accessible`
is the archetype: it is not RDS-only, and on Redshift it *defaults to true*, so
a cluster created without mentioning it is public and silent.
"""

from __future__ import annotations

from typing import Any

from ... import cidr
from ...core import Finding, Severity
from ...plan import ResourceChange
from .shared import (
    PUBLICLY_ACCESSIBLE_TYPES,
    _truthy,
)


class ServiceExposureChecks:
    """Mixed into the NetworkExposure analyzer; see network_exposure.py."""

    def _rds(self, rc: ResourceChange) -> list[Finding]:
        if rc.type not in PUBLICLY_ACCESSIBLE_TYPES:
            return []
        if not _truthy(rc.value("publicly_accessible")):
            return []
        if not rc.is_create and _truthy(rc.prior("publicly_accessible")):
            return []

        return [
            self.finding(
                "NE006",
                "Database instance made publicly accessible",
                Severity.CRITICAL,
                rc.address,
                "publicly_accessible assigns the instance a public IP and a resolvable "
                "public endpoint. The security group is then the only thing between the "
                "database and the internet, and it is edited by a different team than the "
                "one that approved this.",
                evidence={
                    "publicly_accessible": {
                        "before": rc.prior("publicly_accessible"),
                        "after": rc.value("publicly_accessible"),
                    },
                    "engine": rc.value("engine"),
                    "identifier": rc.value("identifier"),
                },
                remediation=(
                    "Set publicly_accessible = false and reach the database over a VPN, "
                    "a peered VPC, or a bastion. If an external consumer needs access, put a "
                    "proxy in front of it rather than the database itself."
                ),
            )
        ]
    def _load_balancer(self, rc: ResourceChange) -> list[Finding]:
        if rc.type not in {"aws_lb", "aws_alb", "aws_elb"}:
            return []

        internal_after = _truthy(rc.value("internal"))
        internal_before = _truthy(rc.prior("internal"))
        newly_public = (rc.is_create and not internal_after) or (
            not rc.is_create and internal_before and not internal_after
        )
        if not newly_public or rc.is_create:
            # A brand new public load balancer is usually the point of the change.
            # Only a transition from internal to internet-facing is reported.
            if not (not rc.is_create and internal_before and not internal_after):
                return []

        return [
            self.finding(
                "NE007",
                "Load balancer changed from internal to internet-facing",
                Severity.HIGH,
                rc.address,
                "This load balancer was reachable only from inside the VPC and will now have "
                "public DNS and public subnet interfaces. Every target behind it inherits "
                "that reachability, including targets added by other teams later.",
                evidence={
                    "internal": {"before": rc.prior("internal"), "after": rc.value("internal")},
                    "name": rc.value("name"),
                    "actions": list(rc.actions),
                },
                remediation=(
                    "Keep the internal load balancer and add a separate public one with an "
                    "explicit target group, so the public surface is a deliberate object "
                    "rather than a flipped boolean."
                ),
            )
        ]
    def _kubernetes(self, rc: ResourceChange) -> list[Finding]:
        if rc.type != "aws_eks_cluster":
            return []

        vpc_after = rc.after.get("vpc_config")
        vpc_before = rc.before.get("vpc_config")
        after_cfg = vpc_after[0] if isinstance(vpc_after, list) and vpc_after else {}
        before_cfg = vpc_before[0] if isinstance(vpc_before, list) and vpc_before else {}
        if not isinstance(after_cfg, dict):
            return []

        if not _truthy(after_cfg.get("endpoint_public_access")):
            return []
        if not rc.is_create and _truthy(before_cfg.get("endpoint_public_access")):
            # Already public; only report the widening of the allow-list below.
            before_cidrs = cidr.parse_all(before_cfg.get("public_access_cidrs"))
            after_cidrs = cidr.parse_all(after_cfg.get("public_access_cidrs"))
            new = cidr.widened(before_cidrs, after_cidrs)
            if not any(cidr.is_world(n) for n in new):
                return []

        allow = after_cfg.get("public_access_cidrs") or []
        nets = cidr.parse_all(allow)
        world = [n for n in nets if cidr.is_world(n)] or (not nets)

        return [
            self.finding(
                "NE010",
                "Kubernetes API server reachable from the internet",
                Severity.CRITICAL if world else Severity.HIGH,
                rc.address,
                "The EKS control plane endpoint is public"
                + (
                    " with no CIDR allow-list, so the API server is exposed to every address "
                    "on the internet and protected only by IAM authentication."
                    if world
                    else f" and restricted to {', '.join(str(n) for n in nets)}."
                ),
                evidence={
                    "endpoint_public_access": {
                        "before": before_cfg.get("endpoint_public_access"),
                        "after": after_cfg.get("endpoint_public_access"),
                    },
                    "public_access_cidrs": allow,
                    "endpoint_private_access": after_cfg.get("endpoint_private_access"),
                },
                remediation=(
                    "Enable endpoint_private_access and either disable public access entirely "
                    "or set public_access_cidrs to the operator and CI egress ranges."
                ),
            )
        ]
    def _public_ip(self, rc: ResourceChange) -> list[Finding]:
        if rc.type == "aws_launch_template":
            return self._launch_template_public_ip(rc)

        field_by_type = {
            "aws_instance": "associate_public_ip_address",
            "aws_subnet": "map_public_ip_on_launch",
        }
        if rc.type not in field_by_type:
            return []
        key = field_by_type[rc.type]
        if not _truthy(rc.value(key)):
            return []
        if not rc.is_create and _truthy(rc.prior(key)):
            return []

        subject = "instances launched into it" if rc.type == "aws_subnet" else "this instance"
        return [
            self.finding(
                "NE011",
                "Resource assigned a public IP address",
                Severity.MEDIUM,
                rc.address,
                f"{key} is being enabled, giving {subject} a routable public address. "
                f"Whether that is reachable then depends entirely on the security group, "
                f"which is a weaker position than not having the address at all.",
                evidence={key: {"before": rc.prior(key), "after": rc.value(key)}},
                remediation=(
                    "Place the resource in a private subnet and use a NAT gateway for "
                    "outbound traffic, or an ALB for inbound."
                ),
            )
        ]
    def _launch_template_public_ip(self, rc: ResourceChange) -> list[Finding]:
        """The attribute lives in a nested block, and applies to future instances."""

        def wants_public(attrs: dict[str, Any]) -> bool:
            interfaces = attrs.get("network_interfaces") or []
            return any(
                _truthy(i.get("associate_public_ip_address"))
                for i in interfaces
                if isinstance(i, dict)
            )

        if not wants_public(rc.after):
            return []
        if not rc.is_create and wants_public(rc.before):
            return []

        return [
            self.finding(
                "NE011",
                "Launch template assigns public IP addresses",
                Severity.MEDIUM,
                rc.address,
                "associate_public_ip_address is enabled on this launch template's network "
                "interface. Every instance created from it gets a routable address, including "
                "instances an autoscaling group creates long after this review.",
                evidence={
                    "network_interfaces": {
                        "before": rc.before.get("network_interfaces"),
                        "after": rc.after.get("network_interfaces"),
                    }
                },
                remediation=(
                    "Launch into private subnets and reach the instances through a load "
                    "balancer or a NAT gateway."
                ),
            )
        ]
