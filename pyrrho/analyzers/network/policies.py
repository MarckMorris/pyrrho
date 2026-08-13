"""Guards, resource policies, prefix lists and network ACLs.

What these have in common is that the dangerous change is a deletion or a
disabled flag rather than an addition. A removed network ACL deny leaves nothing
in the end state to object to; a disabled public access block exposes nothing by
itself and is what precedes a public bucket. Both are invisible to a check that
reads only the planned result.
"""

from __future__ import annotations

from typing import Any

from ... import cidr, policy
from ...core import Finding, Severity
from ...plan import ResourceChange
from .shared import (
    NETWORK_ACL_TYPES,
    PUBLIC_ACCESS_BLOCK_TYPES,
    RESOURCE_POLICY_TYPES,
    _truthy,
)


class PolicyChecks:
    """Mixed into the NetworkExposure analyzer; see network_exposure.py."""

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
