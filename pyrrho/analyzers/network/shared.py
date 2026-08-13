"""Shared vocabulary for the network checks.

Resource type tables, the normalised security group rule, and the small
predicates every check needs. Kept in one place because the type tables are the
part most often wrong by omission -- `aws_default_security_group` is one word
away from `aws_security_group` and applies to every interface in the VPC -- and
a reviewer should be able to read them all at once.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ... import cidr, ports
from ...plan import ResourceChange

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
