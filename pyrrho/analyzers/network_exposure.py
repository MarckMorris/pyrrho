"""Network exposure analyzer: what this plan makes reachable that was not.

The discipline here is delta-only. A security group that already allowed SSH
from the world before this plan ran is a real problem, but it is not *this
pull request's* problem, and reporting it as such is how scanners train people
to ignore them. Every rule in this module compares the planned state against the
prior state and reports the difference.

The one deliberate exception is a resource being created: everything it opens is
new by definition, so all of it is in the delta.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any

from .. import cidr, ports
from ..core import Analyzer, Finding, Severity, register
from ..plan import Plan, ResourceChange

# Terraform resource types that carry security group rules, per provider shape.
INLINE_SG = "aws_security_group"
STANDALONE_SG_RULE = "aws_security_group_rule"
VPC_INGRESS_RULE = "aws_vpc_security_group_ingress_rule"
VPC_EGRESS_RULE = "aws_vpc_security_group_egress_rule"


@dataclass(frozen=True)
class SGRule:
    """A security group rule, normalised across the provider's three shapes."""

    direction: str
    protocol: str
    from_port: int | None
    to_port: int | None
    cidrs: tuple[str, ...]
    description: str = ""

    @property
    def shape(self) -> tuple[str, str, int | None, int | None]:
        """Identity of the rule ignoring its source addresses."""
        return (self.direction, str(self.protocol), self.from_port, self.to_port)

    @property
    def networks(self) -> list[cidr.IPNetwork]:
        return cidr.parse_all(self.cidrs)

    def label(self) -> str:
        return ports.describe(self.from_port, self.to_port, self.protocol)


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _rules_from_inline(attrs: dict[str, Any]) -> list[SGRule]:
    """Rules from an ``aws_security_group`` resource's inline blocks."""
    out: list[SGRule] = []
    for direction in ("ingress", "egress"):
        blocks = attrs.get(direction)
        if not isinstance(blocks, list):
            continue
        for block in blocks:
            if not isinstance(block, dict):
                continue
            cidrs = _str_list(block.get("cidr_blocks")) + _str_list(block.get("ipv6_cidr_blocks"))
            out.append(
                SGRule(
                    direction=direction,
                    protocol=str(block.get("protocol", "")),
                    from_port=_int_or_none(block.get("from_port")),
                    to_port=_int_or_none(block.get("to_port")),
                    cidrs=tuple(sorted(cidrs)),
                    description=str(block.get("description", "") or ""),
                )
            )
    return out


def _rules_from_standalone(attrs: dict[str, Any]) -> list[SGRule]:
    """Rules from the older ``aws_security_group_rule`` resource."""
    direction = str(attrs.get("type", "ingress"))
    if direction not in {"ingress", "egress"}:
        direction = "ingress"
    cidrs = _str_list(attrs.get("cidr_blocks")) + _str_list(attrs.get("ipv6_cidr_blocks"))
    return [
        SGRule(
            direction=direction,
            protocol=str(attrs.get("protocol", "")),
            from_port=_int_or_none(attrs.get("from_port")),
            to_port=_int_or_none(attrs.get("to_port")),
            cidrs=tuple(sorted(cidrs)),
            description=str(attrs.get("description", "") or ""),
        )
    ]


def _rules_from_vpc_rule(attrs: dict[str, Any], direction: str) -> list[SGRule]:
    """Rules from the current ``aws_vpc_security_group_*_rule`` resources."""
    cidrs = [c for c in (attrs.get("cidr_ipv4"), attrs.get("cidr_ipv6")) if isinstance(c, str) and c]
    return [
        SGRule(
            direction=direction,
            protocol=str(attrs.get("ip_protocol", "")),
            from_port=_int_or_none(attrs.get("from_port")),
            to_port=_int_or_none(attrs.get("to_port")),
            cidrs=tuple(sorted(cidrs)),
            description=str(attrs.get("description", "") or ""),
        )
    ]


def extract_rules(rc: ResourceChange, state: str) -> list[SGRule]:
    """Normalised rules from either the ``before`` or the ``after`` of a change."""
    attrs = rc.before if state == "before" else rc.after
    if not attrs:
        return []
    if rc.type == INLINE_SG:
        return _rules_from_inline(attrs)
    if rc.type == STANDALONE_SG_RULE:
        return _rules_from_standalone(attrs)
    if rc.type == VPC_INGRESS_RULE:
        return _rules_from_vpc_rule(attrs, "ingress")
    if rc.type == VPC_EGRESS_RULE:
        return _rules_from_vpc_rule(attrs, "egress")
    return []


def _truthy(value: Any) -> bool:
    """Terraform renders booleans as JSON booleans, but strings turn up too."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return False


@register
class NetworkExposure(Analyzer):
    """Reports what the plan newly exposes to networks it was not exposed to."""

    name = "network-exposure"
    description = (
        "Finds security group openings, lost segmentation and resources becoming "
        "publicly reachable, comparing planned state against prior state."
    )

    SG_TYPES = (INLINE_SG, STANDALONE_SG_RULE, VPC_INGRESS_RULE, VPC_EGRESS_RULE)

    def run(self, plan: Plan) -> list[Finding]:
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
        return findings

    # -- security groups --------------------------------------------------

    def _security_group(self, rc: ResourceChange) -> list[Finding]:
        findings: list[Finding] = []

        # A rule set Terraform cannot resolve until apply cannot be reviewed.
        # Saying so is more useful than reporting "no findings" on it.
        unknown = [k for k in ("ingress", "egress", "cidr_ipv4", "cidr_blocks") if rc.is_unknown(k)]
        if unknown:
            findings.append(
                self.finding(
                    "NE012",
                    "Security group rules are unknown until apply",
                    Severity.MEDIUM,
                    rc.address,
                    f"Terraform cannot resolve {', '.join(unknown)} at plan time, so the "
                    f"exposure this creates cannot be reviewed before it exists.",
                    evidence={"unknown_attributes": unknown, "actions": list(rc.actions)},
                    remediation=(
                        "Replace the computed value with a literal, or gate the apply behind "
                        "a second review that runs against the post-apply state."
                    ),
                )
            )

        before = extract_rules(rc, "before") if not rc.is_create else []
        after = extract_rules(rc, "after")
        if not after:
            return findings

        prior_by_shape: dict[tuple, list[cidr.IPNetwork]] = {}
        for rule in before:
            prior_by_shape.setdefault(rule.shape, []).extend(rule.networks)

        for rule in after:
            findings.extend(self._judge_rule(rc, rule, prior_by_shape.get(rule.shape, [])))
        return findings

    @staticmethod
    def _stamp(findings: list[Finding], key: str) -> list[Finding]:
        """Give every finding from one rule its own identity.

        A security group can have several rules that trip the same check, and
        each is a separate problem to track and to baseline. The key is the
        rule's shape and not its source addresses, because the addresses are
        exactly what changes between runs.
        """
        return [dataclasses.replace(f, key=key) for f in findings]

    def _judge_rule(
        self, rc: ResourceChange, rule: SGRule, prior: list[cidr.IPNetwork]
    ) -> list[Finding]:
        nets = rule.networks
        if not nets:
            return []
        shape_key = f"{rule.direction}/{rule.protocol}/{rule.from_port}-{rule.to_port}"

        # Only the part of the rule that is genuinely new counts.
        new_nets = cidr.widened(prior, nets)
        if not new_nets:
            return []

        findings: list[Finding] = []
        world = [n for n in new_nets if cidr.is_world(n)]
        broad = [n for n in new_nets if not cidr.is_world(n) and cidr.is_broad(n)]
        public = [n for n in new_nets if cidr.is_public(n)]

        if rule.direction == "egress":
            if world and ports.is_all_ports(rule.from_port, rule.to_port, rule.protocol):
                findings.append(
                    self.finding(
                        "NE009",
                        "Unrestricted egress to the internet",
                        Severity.MEDIUM,
                        rc.address,
                        "This plan opens outbound traffic to every address on every port. "
                        "That is the path data leaves by, and it defeats egress filtering "
                        "as a containment control.",
                        evidence={
                            "direction": "egress",
                            "ports": rule.label(),
                            "new_sources": [str(n) for n in world],
                            "previously_allowed": [str(n) for n in prior],
                        },
                        remediation=(
                            "Scope egress to the prefix lists or VPC endpoints the workload "
                            "actually needs. If unrestricted egress is intentional, record it "
                            "in the baseline so the decision is visible."
                        ),
                    )
                )
            return self._stamp(findings, shape_key)

        # Ingress.
        exposed = ports.sensitive_in_range(rule.from_port, rule.to_port, rule.protocol)

        if world and ports.is_all_ports(rule.from_port, rule.to_port, rule.protocol):
            findings.append(
                self.finding(
                    "NE002",
                    "Every port opened to the entire internet",
                    Severity.CRITICAL,
                    rc.address,
                    "This rule admits every protocol on every port from any address on the "
                    "internet. It is equivalent to having no security group at all.",
                    evidence={
                        "ports": rule.label(),
                        "protocol": rule.protocol,
                        "new_sources": [cidr.describe(n) for n in world],
                        "previously_allowed": [str(n) for n in prior],
                        "services_exposed": sorted(set(exposed.values())),
                        "description": rule.description,
                    },
                    remediation=(
                        "Enumerate the ports the workload serves and write one rule per "
                        "service, sourced from a security group ID or a named prefix list "
                        "rather than a CIDR."
                    ),
                )
            )
        elif world and exposed:
            findings.append(
                self.finding(
                    "NE001",
                    "Administrative or data service opened to the internet",
                    Severity.CRITICAL,
                    rc.address,
                    f"This rule exposes {', '.join(sorted(set(exposed.values())))} to any "
                    f"address on the internet. These services authenticate weakly or not at "
                    f"all at the network layer and are scanned continuously.",
                    evidence={
                        "ports": rule.label(),
                        "services_exposed": {str(p): n for p, n in sorted(exposed.items())},
                        "new_sources": [cidr.describe(n) for n in world],
                        "previously_allowed": [str(n) for n in prior],
                        "description": rule.description,
                    },
                    remediation=(
                        "Source the rule from the security group of the client tier, or from "
                        "the VPN/bastion prefix list. For database ports there is no case for "
                        "an internet-facing rule."
                    ),
                )
            )
        elif world:
            port_label = rule.label()
            benign = all(
                p in ports.PUBLIC_BY_DESIGN
                for p in (ports.covered(rule.from_port, rule.to_port) or [])
            )
            findings.append(
                self.finding(
                    "NE003",
                    "New internet-facing ingress rule",
                    Severity.LOW if benign else Severity.HIGH,
                    rc.address,
                    f"This plan newly admits the whole internet on {port_label}."
                    + (
                        " These are the standard web ports, so this is likely intended; it is "
                        "reported so the decision is on the record."
                        if benign
                        else " Confirm this port is meant to be served publicly."
                    ),
                    evidence={
                        "ports": port_label,
                        "new_sources": [cidr.describe(n) for n in world],
                        "previously_allowed": [str(n) for n in prior],
                        "description": rule.description,
                    },
                    remediation=(
                        "If the service is public, front it with a load balancer and keep the "
                        "instance security group closed to the load balancer's group."
                    ),
                )
            )

        if broad and exposed:
            factor = cidr.widening_factor(prior, nets)
            findings.append(
                self.finding(
                    "NE004",
                    "Ingress source widened to a large public block",
                    Severity.HIGH,
                    rc.address,
                    f"The source range for {rule.label()} grew to a block whose membership "
                    f"cannot be enumerated. A rule that names a /8 is not a restriction; it "
                    f"is a restriction-shaped comment.",
                    evidence={
                        "ports": rule.label(),
                        "services_exposed": {str(p): n for p, n in sorted(exposed.items())},
                        "new_sources": [cidr.describe(n) for n in broad],
                        "previously_allowed": [str(n) for n in prior],
                        "widening_factor": (
                            "unbounded" if factor == float("inf") else round(factor, 1)
                        ),
                    },
                    remediation=(
                        "Replace the CIDR with the specific prefixes in use, or reference the "
                        "peer security group directly so the rule tracks membership."
                    ),
                )
            )
        elif public and not world and not broad and exposed and prior:
            factor = cidr.widening_factor(prior, nets)
            if factor > 1.0:
                findings.append(
                    self.finding(
                        "NE004",
                        "Ingress source widened",
                        Severity.MEDIUM,
                        rc.address,
                        f"The source range for {rule.label()} was widened by roughly "
                        f"{'an unbounded factor' if factor == float('inf') else f'{factor:.0f}x'}.",
                        evidence={
                            "ports": rule.label(),
                            "new_sources": [cidr.describe(n) for n in public],
                            "previously_allowed": [str(n) for n in prior],
                            "widening_factor": (
                                "unbounded" if factor == float("inf") else round(factor, 1)
                            ),
                        },
                        remediation="Confirm every address in the new range is meant to reach this port.",
                    )
                )
        return self._stamp(findings, shape_key)

    # -- object storage ---------------------------------------------------

    def _public_access_block(self, rc: ResourceChange) -> list[Finding]:
        if rc.type != "aws_s3_bucket_public_access_block":
            return []

        guards = (
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        )

        if rc.is_delete:
            return [
                self.finding(
                    "NE005",
                    "S3 public access block removed",
                    Severity.CRITICAL,
                    rc.address,
                    "Deleting the public access block removes the account-independent guard "
                    "that stops a bucket policy or ACL from making objects world-readable. "
                    "Nothing else in this plan has to change for the bucket to go public.",
                    evidence={"actions": list(rc.actions), "prior": {g: rc.prior(g) for g in guards}},
                    remediation="Keep the resource and set all four guards to true.",
                )
            ]

        weakened = {
            g: {"before": rc.prior(g), "after": rc.value(g)}
            for g in guards
            if _truthy(rc.prior(g)) and not _truthy(rc.value(g))
        }
        if rc.is_create:
            weakened = {
                g: {"before": None, "after": rc.value(g)}
                for g in guards
                if not _truthy(rc.value(g))
            }
        if not weakened:
            return []

        return [
            self.finding(
                "NE005",
                "S3 public access guard disabled",
                Severity.CRITICAL,
                rc.address,
                f"{', '.join(sorted(weakened))} is being set to false. Each of these is a "
                f"separate safety net; turning one off is what precedes a public bucket, not "
                f"what causes it, which is why it is easy to approve in a diff.",
                evidence={"guards": weakened},
                remediation="Set every guard to true unless there is a documented reason, and record that reason in the baseline.",
            )
        ]

    # -- databases --------------------------------------------------------

    def _rds(self, rc: ResourceChange) -> list[Finding]:
        if rc.type not in {"aws_db_instance", "aws_rds_cluster_instance"}:
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

    # -- load balancers ---------------------------------------------------

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

    # -- subnet-level segmentation ---------------------------------------

    def _network_acl(self, rc: ResourceChange) -> list[Finding]:
        if rc.type not in {"aws_network_acl", "aws_network_acl_rule"}:
            return []

        entries: list[dict[str, Any]] = []
        if rc.type == "aws_network_acl_rule":
            entries = [rc.after]
        else:
            for key in ("ingress", "egress"):
                blocks = rc.after.get(key)
                if isinstance(blocks, list):
                    entries.extend(
                        dict(b, _direction=key) for b in blocks if isinstance(b, dict)
                    )

        findings: list[Finding] = []
        for entry in entries:
            if str(entry.get("rule_action", entry.get("action", "allow"))).lower() != "allow":
                continue
            block = entry.get("cidr_block") or entry.get("ipv6_cidr_block")
            net = cidr.parse(block) if isinstance(block, str) else None
            if net is None or not cidr.is_world(net):
                continue
            findings.append(
                self.finding(
                    "NE008",
                    "Network ACL allows the internet, removing subnet segmentation",
                    Severity.HIGH,
                    rc.address,
                    "A network ACL is the subnet's own boundary and the only control that "
                    "still applies when a security group is misconfigured. An allow-all entry "
                    "here means the subnet has no independent boundary left.",
                    evidence={
                        "rule_number": entry.get("rule_number"),
                        "protocol": entry.get("protocol"),
                        "cidr_block": block,
                        "direction": entry.get("_direction", entry.get("egress")),
                        "from_port": entry.get("from_port"),
                        "to_port": entry.get("to_port"),
                    },
                    key=f"{entry.get('_direction', 'ingress')}/{entry.get('rule_number', entry.get('rule_no', ''))}",
                    remediation=(
                        "Keep the network ACL as a coarse deny boundary between tiers and let "
                        "security groups do the fine-grained work."
                    ),
                )
            )
        return findings

    # -- managed control planes -------------------------------------------

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
        field_by_type = {
            "aws_instance": "associate_public_ip_address",
            "aws_subnet": "map_public_ip_on_launch",
            "aws_launch_template": None,
        }
        if rc.type not in field_by_type:
            return []
        key = field_by_type[rc.type]
        if key is None:
            return []
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
