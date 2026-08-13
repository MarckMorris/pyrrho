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

from .. import cidr, policy, ports
from ..core import Analyzer, Finding, Severity, register
from ..plan import Plan, ResourceChange

# Terraform resource types that carry security group rules, per provider shape.
INLINE_SG = "aws_security_group"
DEFAULT_SG = "aws_default_security_group"
# Same inline ingress/egress shape as aws_security_group, and it applies to
# every network interface in the VPC that has no explicit group, so a rule
# added here has the widest blast radius available.
INLINE_SG_TYPES = (INLINE_SG, DEFAULT_SG)

# Both carry block_public_acls / block_public_policy / ignore_public_acls /
# restrict_public_buckets. The account-wide one removes the guard from every
# bucket at once, which is strictly worse than the per-bucket case.
PUBLIC_ACCESS_BLOCK_TYPES = (
    "aws_s3_bucket_public_access_block",
    "aws_s3_account_public_access_block",
)

# publicly_accessible is not an RDS-only attribute. On aws_redshift_cluster it
# also *defaults to true*, so a cluster created without mentioning it is public.
PUBLICLY_ACCESSIBLE_TYPES = (
    "aws_db_instance",
    "aws_rds_cluster_instance",
    "aws_redshift_cluster",
    "aws_dms_replication_instance",
    "aws_docdb_cluster_instance",
    "aws_neptune_cluster_instance",
)

NETWORK_ACL_TYPES = (
    "aws_network_acl",
    "aws_default_network_acl",
    "aws_network_acl_rule",
)

# Attributes whose value decides what a rule exposes. Any of them being unknown
# at plan time means the exposure cannot be reviewed. The original list held only
# the rule containers, so an unknown port range on a world-open rule was read as
# "no ports", which `all([])` then judged benign.
UNRESOLVABLE_RULE_ATTRIBUTES = (
    "ingress",
    "egress",
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "cidr_ipv4",
    "cidr_ipv6",
    "from_port",
    "to_port",
    "protocol",
    "ip_protocol",
)

# Resource policies decide whether anyone on the internet can read the data.
# Trust policies decide who can become whom, and belong to the privilege
# escalation analyzer instead.
RESOURCE_POLICY_TYPES = {
    "aws_s3_bucket_policy": "S3 bucket",
    "aws_sqs_queue_policy": "SQS queue",
    "aws_sns_topic_policy": "SNS topic",
    "aws_ecr_repository_policy": "container registry",
    "aws_efs_file_system_policy": "EFS filesystem",
    "aws_secretsmanager_secret_policy": "secret",
    "aws_kms_key": "KMS key",
    "aws_glacier_vault": "Glacier vault",
    "aws_api_gateway_rest_api": "API Gateway API",
}
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
    groups: tuple[str, ...] = ()
    prefix_lists: tuple[str, ...] = ()
    index: int = 0

    @property
    def shape(self) -> tuple[str, str, int | None, int | None]:
        """Identity of the rule ignoring its source addresses.

        Used to pair a rule in ``after`` with the same rule in ``before``, so the
        comparison is between two versions of one rule rather than between
        unrelated lines that happen to share a block.
        """
        return (
            self.direction,
            ports.canonical_protocol(self.protocol),
            self.from_port,
            self.to_port,
        )

    def identity(self) -> str:
        """Stable per-rule key, so two rules of the same shape stay distinct.

        A group can hold several rules with identical direction, protocol and
        ports, differing only in source. Keying findings on the shape alone made
        them share a fingerprint, so baselining one accepted rule silently
        suppressed a different rule added to the same group later.

        The description is preferred, because that is how a human tells two rules
        apart. The positional index is the fallback, which is why reordering a
        block of undescribed rules re-mints their baseline entries.
        """
        direction, protocol, from_port, to_port = self.shape
        marker = self.description.strip() or f"#{self.index}"
        return f"{direction}/{protocol}/{from_port}-{to_port}/{marker}"

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
        for position, block in enumerate(blocks):
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
                    groups=tuple(sorted(_str_list(block.get("security_groups")))),
                    prefix_lists=tuple(sorted(_str_list(block.get("prefix_list_ids")))),
                    index=position,
                )
            )
    return out


def _rules_from_standalone(attrs: dict[str, Any]) -> list[SGRule]:
    """Rules from the older ``aws_security_group_rule`` resource."""
    direction = str(attrs.get("type", "ingress"))
    if direction not in {"ingress", "egress"}:
        direction = "ingress"
    cidrs = _str_list(attrs.get("cidr_blocks")) + _str_list(attrs.get("ipv6_cidr_blocks"))
    groups = _str_list(attrs.get("source_security_group_id"))
    return [
        SGRule(
            direction=direction,
            protocol=str(attrs.get("protocol", "")),
            from_port=_int_or_none(attrs.get("from_port")),
            to_port=_int_or_none(attrs.get("to_port")),
            cidrs=tuple(sorted(cidrs)),
            description=str(attrs.get("description", "") or ""),
            groups=tuple(sorted(groups)),
            prefix_lists=tuple(sorted(_str_list(attrs.get("prefix_list_ids")))),
        )
    ]


def _rules_from_vpc_rule(attrs: dict[str, Any], direction: str) -> list[SGRule]:
    """Rules from the current ``aws_vpc_security_group_*_rule`` resources."""
    cidrs = [c for c in (attrs.get("cidr_ipv4"), attrs.get("cidr_ipv6")) if isinstance(c, str) and c]
    groups = _str_list(attrs.get("referenced_security_group_id"))
    return [
        SGRule(
            direction=direction,
            protocol=str(attrs.get("ip_protocol", "")),
            from_port=_int_or_none(attrs.get("from_port")),
            to_port=_int_or_none(attrs.get("to_port")),
            cidrs=tuple(sorted(cidrs)),
            description=str(attrs.get("description", "") or ""),
            groups=tuple(sorted(groups)),
            prefix_lists=tuple(sorted(_str_list(attrs.get("prefix_list_id")))),
        )
    ]


def extract_rules(rc: ResourceChange, state: str) -> list[SGRule]:
    """Normalised rules from either the ``before`` or the ``after`` of a change."""
    attrs = rc.before if state == "before" else rc.after
    if not attrs:
        return []
    if rc.type in INLINE_SG_TYPES:
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

    # -- security groups --------------------------------------------------

    def _security_group(self, rc: ResourceChange) -> list[Finding]:
        findings: list[Finding] = []

        # A rule set Terraform cannot resolve until apply cannot be reviewed.
        # Saying so is more useful than reporting "no findings" on it.
        unknown = [k for k in UNRESOLVABLE_RULE_ATTRIBUTES if rc.is_unknown(k)]
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

        prior_groups = {group for rule in before for group in rule.groups}
        for rule in after:
            findings.extend(self._judge_rule(rc, rule, prior_by_shape.get(rule.shape, [])))
            findings.extend(self._judge_group_source(rc, rule, prior_groups))
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
        """Judge one rule, on the part of its source range that is genuinely new.

        Severity is a function of two things: how far the new sources reach, and
        what is listening. Reach is not "is this block 0.0.0.0/0", because
        ``0.0.0.0/1`` plus ``128.0.0.0/1`` is the same reach written as two
        innocuous-looking CIDRs. See ``cidr.reach``.
        """
        nets = rule.networks
        if not nets:
            return []
        shape_key = rule.identity()

        # Only the part of the rule that is genuinely new counts.
        new_nets = cidr.widened(prior, nets)
        if not new_nets:
            return []

        findings: list[Finding] = []
        reach = cidr.reach(new_nets)
        public = [n for n in new_nets if cidr.is_public(n)]
        all_ports = ports.is_all_ports(rule.from_port, rule.to_port, rule.protocol)
        sources = [cidr.describe(n) for n in new_nets]
        previously = [str(n) for n in prior]

        if rule.direction == "egress":
            if reach == "internet" and all_ports:
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
                            "reach": reach,
                            "new_sources": sources,
                            "previously_allowed": previously,
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
        if not public:
            return []

        exposed = ports.sensitive_in_range(rule.from_port, rule.to_port, rule.protocol)
        span = ports.covered(rule.from_port, rule.to_port)
        # An unbounded or unknown port range is not "no ports"; it is every port
        # we cannot see. Treating it as benign is how a world-open rule with
        # unresolved ports gets reported as if it were HTTPS.
        ports_known = span is not None or all_ports
        serves_web_only = span is not None and all(p in ports.PUBLIC_BY_DESIGN for p in span)

        severity_by_reach = {
            "internet": Severity.CRITICAL,
            "broad": Severity.HIGH,
            "narrow": Severity.MEDIUM,
        }

        if all_ports and reach == "internet":
            findings.append(
                self.finding(
                    "NE002",
                    "Every port opened to the entire internet",
                    Severity.CRITICAL,
                    rc.address,
                    "This rule admits every protocol on every port from any address on the "
                    "internet. It is equivalent to having no security group at all."
                    + (
                        " The sources are written as separate blocks that together cover the "
                        "whole address space, which reads as scoped in a diff."
                        if not any(cidr.is_world(n) for n in new_nets)
                        else ""
                    ),
                    evidence={
                        "ports": rule.label(),
                        "protocol": rule.protocol,
                        "reach": reach,
                        "new_sources": sources,
                        "previously_allowed": previously,
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
        elif exposed:
            severity = severity_by_reach[reach]
            where = {
                "internet": "any address on the internet",
                "broad": "a public block whose membership cannot be enumerated",
                "narrow": "a public address range",
            }[reach]
            findings.append(
                self.finding(
                    "NE001",
                    "Administrative or data service opened to a public network",
                    severity,
                    rc.address,
                    f"This rule exposes {', '.join(sorted(set(exposed.values())))} to {where}. "
                    f"These services authenticate weakly or not at all at the network layer "
                    f"and are scanned continuously.",
                    evidence={
                        "ports": rule.label(),
                        "reach": reach,
                        "services_exposed": {str(p): n for p, n in sorted(exposed.items())},
                        "new_sources": sources,
                        "previously_allowed": previously,
                        "description": rule.description,
                    },
                    remediation=(
                        "Source the rule from the security group of the client tier, or from "
                        "the VPN/bastion prefix list. For database ports there is no case for "
                        "an internet-facing rule."
                    ),
                )
            )
        elif not ports_known:
            findings.append(
                self.finding(
                    "NE003",
                    "Public ingress rule whose ports cannot be determined",
                    Severity.HIGH,
                    rc.address,
                    "This rule admits public traffic, but Terraform cannot resolve the port "
                    "range at plan time. The set of services it exposes is unknown, so it "
                    "cannot be reviewed before it exists.",
                    evidence={
                        "ports": rule.label(),
                        "reach": reach,
                        "new_sources": sources,
                        "previously_allowed": previously,
                        "description": rule.description,
                    },
                    remediation=(
                        "Pin the ports to literals so the exposure is reviewable, or re-run "
                        "this review against the post-apply state."
                    ),
                )
            )
        elif reach == "internet":
            findings.append(
                self.finding(
                    "NE003",
                    "New internet-facing ingress rule",
                    Severity.LOW if serves_web_only else Severity.HIGH,
                    rc.address,
                    f"This plan newly admits the whole internet on {rule.label()}."
                    + (
                        " These are the standard web ports, so this is likely intended; it is "
                        "reported so the decision is on the record."
                        if serves_web_only
                        else " Confirm this port is meant to be served publicly."
                    ),
                    evidence={
                        "ports": rule.label(),
                        "reach": reach,
                        "new_sources": sources,
                        "previously_allowed": previously,
                        "description": rule.description,
                    },
                    remediation=(
                        "If the service is public, front it with a load balancer and keep the "
                        "instance security group closed to the load balancer's group."
                    ),
                )
            )
        elif reach == "broad":
            findings.append(
                self.finding(
                    "NE003",
                    "New ingress from a large public block",
                    Severity.MEDIUM,
                    rc.address,
                    f"This plan admits {rule.label()} from a public block too wide to "
                    f"enumerate. Nothing well known listens there, which is why this is not "
                    f"critical, but nobody can say who is inside the range either.",
                    evidence={
                        "ports": rule.label(),
                        "reach": reach,
                        "new_sources": sources,
                        "previously_allowed": previously,
                        "description": rule.description,
                    },
                    remediation="Replace the block with the specific prefixes in use.",
                )
            )

        factor = cidr.widening_factor(prior, nets) if prior else 1.0
        readable_factor = (
            "unbounded" if factor == float("inf") else round(factor, 1)
        )

        if findings:
            # How much wider the rule got is part of the story of the finding
            # that already fired, not a second finding. Emitting both doubles
            # the alert count for one problem, and the second one always looks
            # like the first one restated.
            if factor > 1.0:
                findings = [
                    dataclasses.replace(
                        f, evidence={**f.evidence, "widening_factor": readable_factor}
                    )
                    for f in findings
                ]
        elif factor > 1.0:
            # Nothing above fired, so the growth itself is the only thing to
            # report: a public range that got bigger without crossing into
            # internet-wide reach or touching a service worth naming.
            findings.append(
                self.finding(
                    "NE004",
                    "Ingress source widened",
                    Severity.MEDIUM,
                    rc.address,
                    f"The source range for {rule.label()} grew by roughly "
                    f"{'an unbounded factor' if factor == float('inf') else f'{factor:.0f}x'}. "
                    f"Nothing well known listens on that port, which is why this is not "
                    f"higher, but the rule admits addresses nobody has enumerated.",
                    evidence={
                        "ports": rule.label(),
                        "reach": reach,
                        "new_sources": sources,
                        "previously_allowed": previously,
                        "widening_factor": readable_factor,
                    },
                    remediation=(
                        "Replace the CIDR with the specific prefixes in use, or reference "
                        "the peer security group directly so the rule tracks membership."
                    ),
                )
            )
        return self._stamp(findings, shape_key)

    # -- object storage ---------------------------------------------------

    def _public_access_block(self, rc: ResourceChange) -> list[Finding]:
        if rc.type not in PUBLIC_ACCESS_BLOCK_TYPES:
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

    def _nacl_entries(self, rc: ResourceChange, state: str) -> list[dict[str, Any]]:
        """Entries from either side of the change, across both resource shapes."""
        attrs = rc.before if state == "before" else rc.after
        if not attrs:
            return []
        if rc.type == "aws_network_acl_rule":
            return [dict(attrs, _direction="egress" if _truthy(attrs.get("egress")) else "ingress")]
        entries: list[dict[str, Any]] = []
        for key in ("ingress", "egress"):
            blocks = attrs.get(key)
            if isinstance(blocks, list):
                entries.extend(dict(b, _direction=key) for b in blocks if isinstance(b, dict))
        return entries

    @staticmethod
    def _nacl_key(entry: dict[str, Any]) -> str:
        number = entry.get("rule_number", entry.get("rule_no", ""))
        return f"{entry.get('_direction', 'ingress')}/{number}"

    @staticmethod
    def _nacl_action(entry: dict[str, Any]) -> str:
        return str(entry.get("rule_action", entry.get("action", "allow"))).lower()

    def _network_acl(self, rc: ResourceChange) -> list[Finding]:
        if rc.type not in NETWORK_ACL_TYPES:
            return []

        before = {self._nacl_key(e): e for e in self._nacl_entries(rc, "before")}
        after = {self._nacl_key(e): e for e in self._nacl_entries(rc, "after")}
        findings: list[Finding] = []

        for key, entry in after.items():
            if self._nacl_action(entry) != "allow":
                continue
            if key in before and self._nacl_action(before[key]) == "allow":
                continue  # the entry was already there; not this change's doing
            block = entry.get("cidr_block") or entry.get("ipv6_cidr_block")
            nets = cidr.parse_all([block] if isinstance(block, str) else [])
            if cidr.reach(nets) != "internet":
                continue
            was_deny = key in before
            findings.append(
                self.finding(
                    "NE008",
                    "Network ACL allows the internet, removing subnet segmentation",
                    Severity.HIGH,
                    rc.address,
                    "A network ACL is the subnet's own boundary and the only control that "
                    "still applies when a security group is misconfigured. "
                    + (
                        "This entry is being flipped from deny to allow, which reads in a diff "
                        "as one word."
                        if was_deny
                        else "An allow-all entry here means the subnet has no independent "
                        "boundary left."
                    ),
                    evidence={
                        "rule_number": entry.get("rule_number", entry.get("rule_no")),
                        "protocol": entry.get("protocol"),
                        "cidr_block": block,
                        "direction": entry.get("_direction"),
                        "from_port": entry.get("from_port"),
                        "to_port": entry.get("to_port"),
                        "previous_action": self._nacl_action(before[key]) if was_deny else None,
                    },
                    remediation=(
                        "Keep the network ACL as a coarse deny boundary between tiers and let "
                        "security groups do the fine-grained work."
                    ),
                    key=key,
                )
            )

        # A deny entry that disappears is the same harm as an allow entry that
        # appears, and it is the shape a scanner reading only `after` cannot see:
        # after the change there is simply nothing there to object to.
        for key, entry in before.items():
            if self._nacl_action(entry) != "deny":
                continue
            if key in after and self._nacl_action(after[key]) == "deny":
                continue
            block = entry.get("cidr_block") or entry.get("ipv6_cidr_block")
            findings.append(
                self.finding(
                    "NE016",
                    "Network ACL deny boundary removed",
                    Severity.HIGH,
                    rc.address,
                    f"A deny entry covering {block} is being removed from the subnet's "
                    f"boundary. Nothing in the planned state records that it ever existed, so "
                    f"this is invisible to anything that reviews the end state rather than the "
                    f"change.",
                    evidence={
                        "rule_number": entry.get("rule_number", entry.get("rule_no")),
                        "protocol": entry.get("protocol"),
                        "cidr_block": block,
                        "direction": entry.get("_direction"),
                        "removed_or_replaced": "replaced" if key in after else "removed",
                        "now": self._nacl_action(after[key]) if key in after else None,
                    },
                    remediation=(
                        "Confirm the traffic this entry denied is blocked somewhere else. A "
                        "security group is not a replacement: it does not apply to the subnet."
                    ),
                    key=key,
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

    # -- cross-resource indexes -------------------------------------------

    def _index_security_groups(self, plan: Plan) -> dict[str, list[SGRule]]:
        """Every security group in the plan, keyed by every id it is known by.

        A rule sourced from ``sg-0abc`` says nothing on its own. It says a great
        deal once you know what ``sg-0abc`` itself admits. Terraform resolves the
        id of a group that already exists, so this link can be followed for the
        common case; a group created in the same plan has an unknown id and the
        link cannot be followed, which ``_judge_group_source`` reports rather
        than passing over.
        """
        index: dict[str, list[SGRule]] = {}
        for rc in plan.resource_changes:
            if rc.type not in INLINE_SG_TYPES:
                continue
            rules = extract_rules(rc, "after") or extract_rules(rc, "before")
            for key in (rc.value("id"), rc.prior("id"), rc.address):
                if isinstance(key, str) and key:
                    index[key] = rules
        return index

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

    # -- transitive exposure through another security group ---------------

    def _judge_group_source(
        self, rc: ResourceChange, rule: SGRule, prior_groups: set[str]
    ) -> list[Finding]:
        """A rule sourced from a group that is itself open to the internet.

        This is the shape people reach for when told not to write a CIDR. It
        looks tighter than `0.0.0.0/0` in review and is worth exactly as much as
        whatever the referenced group admits.
        """
        new_groups = [g for g in rule.groups if g not in prior_groups]
        if not new_groups or rule.direction != "ingress":
            return []

        exposed = ports.sensitive_in_range(rule.from_port, rule.to_port, rule.protocol)
        findings: list[Finding] = []

        for group_id in new_groups:
            upstream = self._groups.get(group_id)
            if upstream is None:
                findings.append(
                    self.finding(
                        "NE014",
                        "Ingress sourced from a security group this plan cannot resolve",
                        Severity.LOW,
                        rc.address,
                        f"The rule admits {rule.label()} from {group_id}, which is not in this "
                        f"plan. Whether that is a tight grant or an open door depends on rules "
                        f"pyrrho cannot see from here.",
                        evidence={
                            "ports": rule.label(),
                            "referenced_group": group_id,
                            "resolved": False,
                        },
                        remediation=(
                            "Review the referenced group by hand, or include it in the same "
                            "plan so the reference can be followed."
                        ),
                        key=f"{rule.identity()}/{group_id}",
                    )
                )
                continue

            open_rules = [
                upstream_rule
                for upstream_rule in upstream
                if upstream_rule.direction == "ingress"
                and cidr.reach(upstream_rule.networks) == "internet"
            ]
            if not open_rules:
                continue

            findings.append(
                self.finding(
                    "NE014",
                    "Ingress sourced from a security group that is itself open to the internet",
                    Severity.HIGH if exposed else Severity.MEDIUM,
                    rc.address,
                    f"The rule admits {rule.label()} from {group_id} instead of a CIDR, which "
                    f"reads as scoped. That group accepts traffic from the whole internet on "
                    f"{', '.join(sorted({r.label() for r in open_rules}))}, so anything that "
                    f"reaches it reaches this resource too."
                    + (
                        f" The exposed services are "
                        f"{', '.join(sorted(set(exposed.values())))}."
                        if exposed
                        else ""
                    ),
                    evidence={
                        "ports": rule.label(),
                        "referenced_group": group_id,
                        "resolved": True,
                        "upstream_open_rules": sorted({r.label() for r in open_rules}),
                        "upstream_sources": sorted(
                            {c for r in open_rules for c in r.cidrs}
                        ),
                        "services_exposed": {str(p): n for p, n in sorted(exposed.items())},
                    },
                    remediation=(
                        "Close the referenced group first, or source this rule from a tier that "
                        "is not internet-facing. Referencing a group is only a restriction if "
                        "the group is one."
                    ),
                    key=f"{rule.identity()}/{group_id}",
                )
            )
        return findings

    # -- routing -----------------------------------------------------------

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

    # -- joining segments that were kept apart ----------------------------

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

    # -- policies that make data publicly readable ------------------------

    def _resource_policy(self, rc: ResourceChange) -> list[Finding]:
        """A resource policy that grants any principal.

        This is not the same question as the S3 public access block. The block is
        the guard; the policy is the thing the guard exists to stop. A bucket
        with no block and a wildcard policy is readable by the world, and nothing
        in the plan's shape says so.
        """
        if rc.type not in RESOURCE_POLICY_TYPES:
            return []

        what = RESOURCE_POLICY_TYPES[rc.type]
        after = policy.parse(rc.value("policy"))
        before = policy.parse(rc.prior("policy")) if not rc.is_create else []
        if not after:
            return []

        delta = policy.diff(before, after)
        candidates = delta.added + [new for _, new in delta.weakened]
        public = [
            statement
            for statement in candidates
            if statement.allows and statement.any_principal and not statement.has_condition
        ]
        if not public:
            return []

        return [
            self.finding(
                "NE017",
                f"{what} policy grants access to any principal",
                Severity.CRITICAL,
                rc.address,
                f"A statement is being added that allows any AWS principal, with no condition "
                f"restricting who that is. Anyone on the internet can call the listed actions. "
                f"The statement reads: {public[0].summary()}",
                evidence={
                    "statements_added": [s.to_dict() for s in public],
                    "actions": sorted({a for s in public for a in s.actions}),
                    "had_a_policy_before": bool(before),
                },
                remediation=(
                    "Name the accounts, roles or organisation that need access. If the data is "
                    "genuinely public, add a condition on aws:SourceArn or aws:SourceVpce so "
                    "the grant is bounded by something."
                ),
                key=public[0].identity()[:80],
            )
        ]

    # -- prefix lists ------------------------------------------------------

    def _prefix_list(self, rc: ResourceChange) -> list[Finding]:
        """A managed prefix list widens every rule that references it at once.

        The security groups do not change. The plan shows one resource. The
        exposure lands on every rule in the account that names this list.
        """
        if rc.type != "aws_ec2_managed_prefix_list":
            return []

        def entries(attrs: dict[str, Any]) -> list[str]:
            raw = attrs.get("entry") or []
            return [e.get("cidr") for e in raw if isinstance(e, dict) and e.get("cidr")]

        after = cidr.parse_all(entries(rc.after))
        before = cidr.parse_all(entries(rc.before)) if not rc.is_create else []
        new = cidr.widened(before, after)
        if not new:
            return []

        reach = cidr.reach(new)
        if reach == "narrow":
            return []

        return [
            self.finding(
                "NE018",
                "Managed prefix list widened",
                Severity.CRITICAL if reach == "internet" else Severity.HIGH,
                rc.address,
                f"This prefix list gains {', '.join(cidr.describe(n) for n in new)}. Every "
                f"security group rule that references the list widens with it, and none of "
                f"those rules appear in this plan.",
                evidence={
                    "name": rc.value("name"),
                    "reach": reach,
                    "entries_added": [str(n) for n in new],
                    "previously": [str(n) for n in before],
                    "max_entries": rc.value("max_entries"),
                },
                remediation=(
                    "Find every rule that references this list before approving. A prefix "
                    "list is a shared control surface, not a local one."
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


def _reaches_internet(route: Any) -> bool:
    """True for a route that sends traffic to an internet gateway.

    Both the ordinary and the egress-only gateway count: the first makes a subnet
    reachable, the second makes it able to reach out over IPv6.
    """
    if not isinstance(route, dict):
        return False
    gateway = str(route.get("gateway_id") or route.get("egress_only_gateway_id") or "")
    if not gateway.startswith(("igw-", "eigw-")):
        return False
    destination = route.get("destination_cidr_block") or route.get(
        "destination_ipv6_cidr_block"
    )
    nets = cidr.parse_all([destination] if isinstance(destination, str) else [])
    return bool(nets) and cidr.reach(nets) == "internet"
