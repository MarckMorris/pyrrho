"""Reading and diffing IAM policy documents.

Two analyzers need this: network exposure cares about *resource* policies, which
decide whether anyone on the internet can read a bucket or a queue, and
privilege escalation cares about *identity* and *trust* policies, which decide
who can become whom.

The shared problem is that an IAM policy in a Terraform plan is a string
containing JSON, whose fields are individually either a scalar or a list, and
which may be absent, unparseable, or unknown until apply. Every one of those
cases has to survive without an exception, because a review that crashes on one
resource silently stops reviewing the rest of the plan.

The other shared requirement is the delta. Reporting that a policy grants `s3:*`
is close to useless when it granted `s3:*` yesterday too. What matters is the
statement that was not there before, or the condition that was there and is not.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

# Wildcards, in the two spellings IAM accepts.
ANY = {"*", "arn:aws:iam::*:root"}


def as_list(value: Any) -> list[Any]:
    """IAM fields are a scalar or a list, interchangeably. Normalise to a list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def as_strings(value: Any) -> list[str]:
    return [v for v in as_list(value) if isinstance(v, str)]


def loads(value: Any) -> dict[str, Any] | None:
    """Parse a policy that may arrive as a JSON string or an already-parsed dict.

    Returns None when there is nothing usable, rather than raising: a policy the
    plan cannot show us is a fact to report, not a reason to abort.
    """
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


@dataclass(frozen=True)
class Statement:
    """One statement of a policy document, with its fields normalised."""

    effect: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_resources: tuple[str, ...]
    principals: tuple[str, ...]
    not_principals: tuple[str, ...]
    conditions: dict[str, Any] = field(default_factory=dict)
    sid: str = ""

    @property
    def allows(self) -> bool:
        return self.effect.lower() == "allow"

    @property
    def has_condition(self) -> bool:
        return bool(self.conditions)

    @property
    def any_action(self) -> bool:
        return any(a == "*" for a in self.actions)

    @property
    def any_resource(self) -> bool:
        return any(r == "*" for r in self.resources)

    @property
    def any_principal(self) -> bool:
        return any(p in ANY for p in self.principals)

    def matches_action(self, wanted: str) -> bool:
        """Whether this statement grants an action, honouring IAM's prefix globs.

        ``iam:*`` grants ``iam:PassRole``; ``*`` grants everything; an exact
        match grants itself. Case is ignored because IAM ignores it.
        """
        target = wanted.lower()
        for action in self.actions:
            candidate = action.lower()
            if candidate == "*":
                return True
            if candidate.endswith("*") and target.startswith(candidate[:-1]):
                return True
            if candidate == target:
                return True
        return False

    def identity(self) -> str:
        """Stable key for pairing a statement across before and after.

        The Sid is the author's own name for the statement and is used when
        present. Otherwise the shape of the grant serves, which means editing a
        statement's condition is seen as a change to that statement rather than
        as one statement removed and a different one added.
        """
        if self.sid:
            return f"sid:{self.sid}"
        return "|".join(
            [
                self.effect.lower(),
                ",".join(sorted(self.actions)),
                ",".join(sorted(self.not_actions)),
                ",".join(sorted(self.resources)),
                ",".join(sorted(self.not_resources)),
                ",".join(sorted(self.principals)),
            ]
        )

    def summary(self) -> str:
        """One line a human can read in a finding message."""
        verb = "Allow" if self.allows else "Deny"
        actions = ", ".join(self.actions[:4]) or ("NotAction " + ", ".join(self.not_actions[:4]))
        resources = ", ".join(self.resources[:3]) or (
            "NotResource " + ", ".join(self.not_resources[:3])
        )
        line = f"{verb} {actions} on {resources}"
        if self.principals:
            line += f" for {', '.join(self.principals[:3])}"
        if self.conditions:
            line += f" if {', '.join(sorted(self.conditions))}"
        return line

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"effect": self.effect}
        if self.sid:
            out["sid"] = self.sid
        for name, values in (
            ("actions", self.actions),
            ("not_actions", self.not_actions),
            ("resources", self.resources),
            ("not_resources", self.not_resources),
            ("principals", self.principals),
            ("not_principals", self.not_principals),
        ):
            if values:
                out[name] = list(values)
        if self.conditions:
            out["conditions"] = self.conditions
        return out


def _principals(raw: Any) -> list[str]:
    """Flatten the Principal field, which is a string or a map of lists.

    ``"Principal": "*"`` and ``"Principal": {"AWS": "*"}`` mean the same thing
    and both turn up in the wild.
    """
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return as_strings(raw)
    if isinstance(raw, dict):
        out: list[str] = []
        for value in raw.values():
            out.extend(as_strings(value))
        return out
    return []


def statements(document: dict[str, Any] | None) -> list[Statement]:
    """Every statement of a policy, normalised. Empty list for anything unusable."""
    if not document:
        return []
    raw = document.get("Statement")
    if raw is None:
        return []
    out: list[Statement] = []
    for entry in as_list(raw):
        if not isinstance(entry, dict):
            continue
        conditions = entry.get("Condition")
        out.append(
            Statement(
                effect=str(entry.get("Effect", "Allow")),
                actions=tuple(as_strings(entry.get("Action"))),
                not_actions=tuple(as_strings(entry.get("NotAction"))),
                resources=tuple(as_strings(entry.get("Resource"))),
                not_resources=tuple(as_strings(entry.get("NotResource"))),
                principals=tuple(_principals(entry.get("Principal"))),
                not_principals=tuple(_principals(entry.get("NotPrincipal"))),
                conditions=conditions if isinstance(conditions, dict) else {},
                sid=str(entry.get("Sid", "") or ""),
            )
        )
    return out


def parse(value: Any) -> list[Statement]:
    """Convenience: from a raw plan attribute straight to statements."""
    return statements(loads(value))


@dataclass
class PolicyDelta:
    """What changed between two versions of a policy document."""

    added: list[Statement] = field(default_factory=list)
    removed: list[Statement] = field(default_factory=list)
    weakened: list[tuple[Statement, Statement]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.weakened)


def diff(before: Iterable[Statement], after: Iterable[Statement]) -> PolicyDelta:
    """Compare two policies statement by statement.

    ``weakened`` holds pairs where a statement survived but lost a condition, or
    gained actions or resources. That case is the one a whole-policy scanner
    cannot report, because the statement was already there and still is: only
    the comparison shows that its guard rail came off.
    """
    before_by_id = {s.identity(): s for s in before}
    after_by_id = {s.identity(): s for s in after}

    added = [s for key, s in after_by_id.items() if key not in before_by_id]
    removed = [s for key, s in before_by_id.items() if key not in after_by_id]

    weakened: list[tuple[Statement, Statement]] = []
    for key, new in after_by_id.items():
        old = before_by_id.get(key)
        if old is None or not new.allows:
            continue
        lost_conditions = set(old.conditions) - set(new.conditions)
        gained_actions = set(new.actions) - set(old.actions)
        gained_resources = set(new.resources) - set(old.resources)
        gained_principals = set(new.principals) - set(old.principals)
        if lost_conditions or gained_actions or gained_resources or gained_principals:
            weakened.append((old, new))

    return PolicyDelta(added=added, removed=removed, weakened=weakened)
