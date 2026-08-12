"""Core data model, severity ordering and analyzer registry for pyrrho.

The shape here is deliberately boring: a finding is a plain frozen dataclass
carrying its own evidence, and a report is a list of findings plus a verdict.
Everything downstream (SARIF, baseline, attestation, the CLI renderer) is a pure
function of a Report, which is what makes the whole tool testable without a
cloud account, a network, or a Terraform binary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator


class Severity(str, Enum):
    """Severity of a finding, ordered from most to least serious."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank < other.rank

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from exc


class Verdict(str, Enum):
    """What the reviewer concluded about the plan as a whole."""

    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class Finding:
    """One thing the reviewer objects to, with the evidence that justifies it.

    ``evidence`` is not decoration. Every rule must put the concrete values it
    read out of the plan in here, so a human can check the claim without
    re-running the tool and without trusting it.
    """

    rule_id: str
    title: str
    severity: Severity
    analyzer: str
    resource: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    suppressed: bool = False
    key: str = ""

    @property
    def counts(self) -> bool:
        """A finding only affects the verdict when it is not waived by a baseline."""
        return not self.suppressed

    @property
    def fingerprint(self) -> str:
        """Stable identity across runs: same rule, same resource, same aspect.

        Deliberately excludes ``detail`` and ``evidence`` so that a value change
        (a CIDR moving from /8 to /12) does not mint a brand-new alert while the
        underlying problem is still the same one.

        ``key`` is what keeps two findings of the same rule on the same resource
        apart. One resource can drop deletion protection *and* enable
        skip_final_snapshot, and those are two problems: without the key they
        would collapse into one alert, and baselining either would silently
        suppress the other.
        """
        seed = f"{self.rule_id}|{self.resource}|{self.key}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "analyzer": self.analyzer,
            "resource": self.resource,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "suppressed": self.suppressed,
            "key": self.key,
            "fingerprint": self.fingerprint,
        }


@dataclass
class Report:
    """Findings from one review of one plan, plus the metadata to reproduce it."""

    plan_path: str = ""
    plan_digest: str = ""
    terraform_version: str = ""
    format_version: str = ""
    analyzers: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    resources_examined: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    @property
    def counted(self) -> list[Finding]:
        return [f for f in self.findings if f.counts]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    @property
    def worst(self) -> Severity | None:
        if not self.counted:
            return None
        return max((f.severity for f in self.counted), key=lambda s: s.rank)

    def exceeds(self, threshold: Severity) -> bool:
        """True when any counted finding is at or above the given severity."""
        worst = self.worst
        return worst is not None and worst.rank >= threshold.rank

    def verdict(self, threshold: Severity) -> Verdict:
        if self.exceeds(threshold):
            return Verdict.BLOCK
        if self.counted:
            return Verdict.WARN
        return Verdict.PASS

    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.counted:
            counts[f.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        """Most severe first; ties broken deterministically so output is stable."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.rule_id, f.resource, f.key),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": {
                "path": self.plan_path,
                "digest": self.plan_digest,
                "terraform_version": self.terraform_version,
                "format_version": self.format_version,
            },
            "analyzers": sorted(self.analyzers),
            "resources_examined": self.resources_examined,
            "total": len(self.findings),
            "counted": len(self.counted),
            "suppressed": len(self.suppressed),
            "worst_severity": self.worst.value if self.worst else None,
            "by_severity": self.by_severity(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def canonical_json(self) -> str:
        """Byte-stable serialisation, used as the input to the attestation hash."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class Analyzer:
    """Base class for an analyzer. Subclass it and implement ``run``."""

    name: str = ""
    description: str = ""

    def configure(self, **options: Any) -> None:
        """Apply run-time options from the CLI. Analyzers that take none ignore this."""
        return None

    def run(self, plan: Any) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        rule_id: str,
        title: str,
        severity: Severity,
        resource: str,
        detail: str,
        evidence: dict[str, Any] | None = None,
        remediation: str = "",
        key: str = "",
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            analyzer=self.name,
            resource=resource,
            detail=detail,
            evidence=evidence or {},
            remediation=remediation,
            key=key,
        )


REGISTRY: dict[str, type[Analyzer]] = {}


def register(cls: type[Analyzer]) -> type[Analyzer]:
    """Class decorator that adds an analyzer to the global registry."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must define a name")
    if cls.name in REGISTRY:
        raise ValueError(f"duplicate analyzer name: {cls.name}")
    REGISTRY[cls.name] = cls
    return cls


def available() -> list[str]:
    return sorted(REGISTRY)


def resolve(names: list[str] | None, **options: Any) -> list[Analyzer]:
    """Instantiate the requested analyzers, or all of them when none are named.

    Any keyword options are passed to every analyzer's ``configure`` hook; the
    ones that do not care ignore them.
    """
    wanted = list(names) if names else available()
    chosen: list[Analyzer] = []
    for name in wanted:
        if name not in REGISTRY:
            valid = ", ".join(available())
            raise ValueError(f"unknown analyzer {name!r}; available: {valid}")
        analyzer = REGISTRY[name]()
        analyzer.configure(**options)
        chosen.append(analyzer)
    return chosen
