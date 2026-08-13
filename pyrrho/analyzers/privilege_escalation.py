"""Privilege escalation analyzer: the IAM *delta*, not the whole policy.

Every IAM scanner will tell you a policy contains `Action: "*"`. That is close to
useless on a real estate, because it was already there yesterday and the day
before, and the reviewer has learned to scroll past it. The question worth asking
of a pull request is narrower and much harder to answer by looking at the end
state: **what can this identity do after the change that it could not do
before?**

Answering it needs three things the whole-policy approach does not do:

* Pair statements across `before` and `after` so an edit is seen as an edit,
  rather than as one statement removed and an unrelated one added.
* Notice a condition that *disappeared*. The statement is unchanged in every
  visible way, still grants the same actions on the same resources, and is now
  unbounded. Nothing about the end state says a guard rail came off.
* Distinguish an identity policy from a trust policy. `sts:AssumeRole` in the
  first is a grant to go somewhere; in the second it is a grant for someone else
  to arrive.

The escalation primitives below are the well-documented ones: permissions that
do not look like administrator access but can be turned into it in one or two
steps. `iam:PassRole` with a wildcard resource plus the ability to launch
anything is the classic pair.
"""

from __future__ import annotations

from .. import policy
from ..core import Analyzer, Finding, Severity, register
from ..plan import Plan, ResourceChange

# Resources whose `policy` attribute is an identity policy: what the holder may do.
IDENTITY_POLICY_TYPES = {
    "aws_iam_policy": "managed policy",
    "aws_iam_role_policy": "inline role policy",
    "aws_iam_user_policy": "inline user policy",
    "aws_iam_group_policy": "inline group policy",
}

# Resources whose policy says who may *become* this identity.
TRUST_POLICY_TYPES = {
    "aws_iam_role": "assume_role_policy",
}

# Attaching one of these is administrator access under another name.
DANGEROUS_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess": "full administrator access",
    "arn:aws:iam::aws:policy/IAMFullAccess": "the ability to grant itself anything else",
    "arn:aws:iam::aws:policy/PowerUserAccess": "everything except IAM",
    "arn:aws:iam::aws:policy/AWSCloudFormationFullAccess": (
        "the ability to create any resource CloudFormation can create"
    ),
}

# Permissions that convert into administrator access in one or two steps. Each
# entry says what the step actually is, because "this is an escalation path" on
# its own is not something a reviewer can act on.
ESCALATION_PRIMITIVES: dict[str, str] = {
    "iam:CreatePolicyVersion": "write a new default version of any policy, granting anything",
    "iam:SetDefaultPolicyVersion": "roll a policy back to an older, more permissive version",
    "iam:AttachUserPolicy": "attach AdministratorAccess to itself",
    "iam:AttachRolePolicy": "attach AdministratorAccess to a role it can assume",
    "iam:AttachGroupPolicy": "attach AdministratorAccess to a group it belongs to",
    "iam:PutUserPolicy": "write an inline policy on itself granting anything",
    "iam:PutRolePolicy": "write an inline policy on a role it can assume",
    "iam:PutGroupPolicy": "write an inline policy on its own group",
    "iam:CreateAccessKey": "mint credentials for a more privileged user",
    "iam:CreateLoginProfile": "set a console password on a more privileged user",
    "iam:UpdateLoginProfile": "reset the console password of a more privileged user",
    "iam:UpdateAssumeRolePolicy": "rewrite a role's trust policy to let itself in",
    "iam:CreateServiceLinkedRole": "create a role with a service-managed policy",
    "sts:AssumeRole": "become another identity",
    "lambda:UpdateFunctionCode": "replace the code of a function that runs as a stronger role",
    "lambda:CreateFunction": "run arbitrary code as a role it can pass",
    "glue:UpdateDevEndpoint": "run arbitrary code as the endpoint's role",
    "cloudformation:CreateStack": "create any resource the stack role can create",
    "ec2:RunInstances": "start an instance carrying a role it can pass",
    "ssm:SendCommand": "run commands on any instance the agent is installed on",
    "ssm:StartSession": "open a shell on any instance",
    "eks:CreateCluster": "create a cluster whose node role it controls",
    "secretsmanager:GetSecretValue": "read every secret in the account",
    "kms:Decrypt": "decrypt anything the key protects",
}

# The pairing that turns "can launch things" into "can launch things as anyone".
PASS_ROLE = "iam:PassRole"


def _wildcard_principals(statement: policy.Statement) -> list[str]:
    """Principals in a trust policy that are not a specific, named identity."""
    loose: list[str] = []
    for principal in statement.principals:
        if principal in policy.ANY or principal.endswith(":root") or "*" in principal:
            loose.append(principal)
    return loose


@register
class PrivilegeEscalation(Analyzer):
    """Reports what an identity can do after this change that it could not before."""

    name = "privilege-escalation"
    description = (
        "Diffs IAM policies statement by statement and reports the delta: new "
        "wildcards, PassRole pairings, weakened trust policies, removed conditions "
        "and escalation primitives."
    )

    def run(self, plan: Plan) -> list[Finding]:
        findings: list[Finding] = []
        for rc in plan.effective_changes:
            findings.extend(self._identity_policy(rc))
            findings.extend(self._trust_policy(rc))
            findings.extend(self._managed_attachment(rc))
        return findings

    # -- identity policies -------------------------------------------------

    def _identity_policy(self, rc: ResourceChange) -> list[Finding]:
        if rc.type not in IDENTITY_POLICY_TYPES:
            return []
        what = IDENTITY_POLICY_TYPES[rc.type]

        if rc.is_unknown("policy"):
            return [
                self.finding(
                    "PE008",
                    "IAM policy is unknown until apply",
                    Severity.MEDIUM,
                    rc.address,
                    f"Terraform cannot resolve this {what} at plan time. Approving the change "
                    f"approves a set of permissions nobody has read.",
                    evidence={"unknown_attributes": rc.unknown_keys(), "actions": list(rc.actions)},
                    remediation=(
                        "Render the policy from a data source that resolves at plan time, or "
                        "re-run this review against the post-apply state."
                    ),
                )
            ]

        after = policy.parse(rc.value("policy"))
        before = policy.parse(rc.prior("policy")) if not rc.is_create else []
        if not after:
            return []

        delta = policy.diff(before, after)
        findings: list[Finding] = []
        # Both a brand-new statement and a statement that lost its guard rail are
        # grants that did not effectively exist before this change.
        granted = delta.added + [new for _, new in delta.weakened]

        for statement in granted:
            if not statement.allows:
                continue
            findings.extend(self._judge_statement(rc, what, statement, before))

        for old, new in delta.weakened:
            lost = sorted(set(old.conditions) - set(new.conditions))
            if not lost:
                continue
            findings.append(
                self.finding(
                    "PE005",
                    "Condition removed from an existing Allow statement",
                    Severity.HIGH,
                    rc.address,
                    f"The statement still grants the same actions on the same resources, and "
                    f"the condition that bounded it is gone: {', '.join(lost)}. Nothing about "
                    f"the resulting policy records that the guard rail was ever there, which "
                    f"is why a check that reads only the end state cannot report this.",
                    evidence={
                        "statement": new.to_dict(),
                        "conditions_removed": lost,
                        "conditions_before": old.conditions,
                        "actions": list(new.actions),
                    },
                    remediation=(
                        "Put the condition back, or explain in the change description what "
                        "now enforces the boundary it was enforcing."
                    ),
                    key=f"condition:{new.identity()[:60]}",
                )
            )

        return findings

    def _judge_statement(
        self,
        rc: ResourceChange,
        what: str,
        statement: policy.Statement,
        before: list[policy.Statement],
    ) -> list[Finding]:
        findings: list[Finding] = []
        key = statement.identity()[:60]

        if statement.any_action and statement.any_resource:
            findings.append(
                self.finding(
                    "PE001",
                    "Statement grants every action on every resource",
                    Severity.CRITICAL,
                    rc.address,
                    f"This {what} gains a statement equivalent to AdministratorAccess: "
                    f"{statement.summary()}. Whatever the change was for, this grants the rest "
                    f"of the account as well.",
                    evidence={"statement": statement.to_dict()},
                    remediation=(
                        "Name the actions and the resource ARNs the workload needs. If the "
                        "list is genuinely unknown, grant it in a separate, temporary policy "
                        "with an expiry rather than folding it into this one."
                    ),
                    key=f"admin:{key}",
                )
            )
        elif statement.any_action:
            findings.append(
                self.finding(
                    "PE001",
                    "Statement grants every action",
                    Severity.HIGH,
                    rc.address,
                    f"This {what} gains `Action: \"*\"`, scoped to "
                    f"{', '.join(statement.resources[:3])}. Every future API added to those "
                    f"services is granted in advance.",
                    evidence={"statement": statement.to_dict()},
                    remediation="Enumerate the actions the workload calls.",
                    key=f"anyaction:{key}",
                )
            )

        if statement.not_actions or statement.not_resources:
            findings.append(
                self.finding(
                    "PE006",
                    "Allow statement written with NotAction or NotResource",
                    Severity.HIGH,
                    rc.address,
                    "An Allow with NotAction grants everything except a list, which means it "
                    "silently grants every service AWS launches from now on. It is almost "
                    "always meant to be a Deny.",
                    evidence={"statement": statement.to_dict()},
                    remediation=(
                        "Invert it: Allow the specific actions, or move the exclusion into a "
                        "Deny statement, where NotAction is the right tool."
                    ),
                    key=f"notaction:{key}",
                )
            )

        if statement.matches_action(PASS_ROLE):
            wildcard_target = statement.any_resource or any(
                "*" in r for r in statement.resources
            )
            findings.append(
                self.finding(
                    "PE002",
                    "iam:PassRole granted with an unrestricted target",
                    Severity.CRITICAL if wildcard_target else Severity.MEDIUM,
                    rc.address,
                    "iam:PassRole lets the holder hand a role to a service it starts. "
                    + (
                        "With a wildcard resource, that is any role in the account, including "
                        "roles far more privileged than this one. Paired with ec2:RunInstances "
                        "or lambda:CreateFunction it is a direct path to administrator."
                        if wildcard_target
                        else "The target is scoped, which is the right shape; confirm the named "
                        "role is no more privileged than the caller needs."
                    ),
                    evidence={
                        "statement": statement.to_dict(),
                        "resources": list(statement.resources),
                        "paired_with": sorted(
                            action
                            for action in ("ec2:RunInstances", "lambda:CreateFunction", "ecs:RunTask")
                            if statement.matches_action(action)
                        ),
                    },
                    remediation=(
                        "Restrict the Resource to the exact role ARNs, and add an "
                        "iam:PassedToService condition so the role can only be handed to the "
                        "service that should receive it."
                    ),
                    key=f"passrole:{key}",
                )
            )

        primitives = {
            action: how
            for action, how in ESCALATION_PRIMITIVES.items()
            if statement.matches_action(action)
        }
        # A statement that already granted everything is reported once as PE001;
        # re-listing every primitive it implies would bury that.
        if primitives and not statement.any_action:
            already = {
                action
                for old in before
                if old.allows
                for action in primitives
                if old.matches_action(action)
            }
            fresh = {a: how for a, how in primitives.items() if a not in already}
            if fresh:
                findings.append(
                    self.finding(
                        "PE004",
                        "Privilege escalation primitive granted",
                        Severity.HIGH,
                        rc.address,
                        "These permissions do not read as administrator access and convert "
                        "into it: "
                        + "; ".join(f"{a} lets the holder {how}" for a, how in sorted(fresh.items())[:3])
                        + ".",
                        evidence={
                            "statement": statement.to_dict(),
                            "primitives": dict(sorted(fresh.items())),
                            "resources": list(statement.resources),
                            "already_held": sorted(already),
                        },
                        remediation=(
                            "Scope the Resource to the specific policies, roles or functions "
                            "involved. For iam:* actions, a condition on iam:PolicyARN or a "
                            "permissions boundary is what keeps the grant from being circular."
                        ),
                        key=f"primitive:{key}",
                    )
                )

        return findings

    # -- trust policies ----------------------------------------------------

    def _trust_policy(self, rc: ResourceChange) -> list[Finding]:
        attribute = TRUST_POLICY_TYPES.get(rc.type)
        if not attribute:
            return []

        after = policy.parse(rc.value(attribute))
        before = policy.parse(rc.prior(attribute)) if not rc.is_create else []
        if not after:
            return []

        delta = policy.diff(before, after)
        findings: list[Finding] = []

        for statement in delta.added + [new for _, new in delta.weakened]:
            if not statement.allows:
                continue
            loose = _wildcard_principals(statement)
            if not loose:
                continue
            unconditional = not statement.has_condition
            findings.append(
                self.finding(
                    "PE003",
                    "Role trust policy accepts an unbounded principal",
                    Severity.CRITICAL if unconditional else Severity.HIGH,
                    rc.address,
                    f"The role's trust policy now accepts {', '.join(loose)}"
                    + (
                        " with no condition restricting who that is. Anyone who can call "
                        "sts:AssumeRole can become this role, and the role's own permissions "
                        "become theirs."
                        if unconditional
                        else " but a condition narrows it. Confirm the condition is on "
                        "something the caller cannot set for themselves."
                    ),
                    evidence={
                        "statement": statement.to_dict(),
                        "principals": list(statement.principals),
                        "conditions": statement.conditions,
                        "role_name": rc.value("name"),
                    },
                    remediation=(
                        "Name the account, role or OIDC subject that should be able to assume "
                        "this role. For a cross-account grant, add an ExternalId condition; "
                        "for a federated one, condition on the sub claim, not just the issuer."
                    ),
                    key=f"trust:{statement.identity()[:60]}",
                )
            )
        return findings

    # -- managed policy attachments ---------------------------------------

    def _managed_attachment(self, rc: ResourceChange) -> list[Finding]:
        attachment_types = {
            "aws_iam_role_policy_attachment": "role",
            "aws_iam_user_policy_attachment": "user",
            "aws_iam_group_policy_attachment": "group",
            "aws_iam_policy_attachment": "identity",
        }
        if rc.type not in attachment_types:
            return []
        if rc.is_delete:
            return []

        arn = rc.value("policy_arn")
        if not isinstance(arn, str) or arn == rc.prior("policy_arn"):
            return []
        what = DANGEROUS_MANAGED_POLICIES.get(arn)
        if not what:
            return []

        subject = attachment_types[rc.type]
        return [
            self.finding(
                "PE007",
                "Broad AWS-managed policy attached",
                Severity.CRITICAL if "Administrator" in arn or "IAMFull" in arn else Severity.HIGH,
                rc.address,
                f"This attaches {arn.rsplit('/', 1)[-1]} to a {subject}, which grants {what}. "
                f"Managed policy attachments are one line in a plan and are easy to approve as "
                f"boilerplate.",
                evidence={
                    "policy_arn": arn,
                    "grants": what,
                    "target": rc.value("role") or rc.value("user") or rc.value("groups"),
                },
                remediation=(
                    "Write a policy with the actions this workload calls. If administrator "
                    "access is genuinely needed, attach it to a role that has to be assumed "
                    "deliberately rather than to a long-lived identity."
                ),
                key=arn,
            )
        ]
