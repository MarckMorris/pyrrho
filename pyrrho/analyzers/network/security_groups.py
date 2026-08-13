"""Security group rules: what a change newly admits, and from where.

Two things make this more than a string comparison. Reach is computed by
collapsing the source set, so `0.0.0.0/1` plus `128.0.0.0/1` is recognised as
the whole internet rather than two ordinary CIDRs. And a rule sourced from
another security group is followed into that group, because referencing a group
is only a restriction if the group is one.
"""

from __future__ import annotations

import dataclasses

from ... import cidr, ports
from ...core import Finding, Severity
from ...plan import Plan, ResourceChange
from .shared import (
    INLINE_SG_TYPES,
    SGRule,
    UNRESOLVABLE_RULE_ATTRIBUTES,
    extract_rules,
)


class SecurityGroupChecks:
    """Mixed into the NetworkExposure analyzer; see network_exposure.py."""

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
