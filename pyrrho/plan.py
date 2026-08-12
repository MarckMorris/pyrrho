"""Reader for the JSON produced by ``terraform show -json <planfile>``.

Terraform's plan JSON is documented and stable, but it is also easy to misread
in ways that produce a confidently wrong review. Three traps this module exists
to handle explicitly:

* A replacement is not a single action. It is ``["delete", "create"]``, or
  ``["create", "delete"]`` when ``create_before_destroy`` is set. Those two mean
  very different things for downtime and the difference is invisible if you only
  look at ``actions[0]``.
* ``after`` is not the final state. Anything Terraform cannot know until apply
  is absent from ``after`` and marked ``true`` in ``after_unknown``. A scanner
  that reads only ``after`` will cheerfully report that a security group has no
  ingress rules when in fact it has rules that are computed at apply time.
* Sensitive values are redacted from ``before``/``after`` and flagged in
  ``before_sensitive``/``after_sensitive``, which may be ``false``, ``true`` or a
  nested structure. Treating it as always-a-dict raises on real plans.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUPPORTED_FORMAT_MAJOR = 1

# Two documents in the wild carry the same plan, under different top-level keys.
#
#   LOCAL_PLAN  what `terraform show -json <planfile>` writes. Key: format_version.
#   HCP_PLAN    the redacted plan HCP Terraform (formerly Terraform Cloud) serves
#               from its run API, which is what a team using remote execution
#               actually has to hand. Key: plan_format_version, no
#               terraform_version, and provider schemas attached.
#
# The resource_changes structure is identical in both, which is why supporting
# the second costs one line and rejecting it would have made the tool useless to
# anyone running Terraform remotely.
LOCAL_PLAN = "terraform show -json"
HCP_PLAN = "HCP Terraform redacted plan"


class PlanFormatError(ValueError):
    """The input is not a Terraform plan JSON document we can read."""


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a plan field that may be dict, ``true``, ``false`` or absent."""
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class ResourceChange:
    """One entry of ``resource_changes``, with the action semantics decoded."""

    address: str
    type: str
    name: str
    mode: str
    provider: str
    module_address: str
    actions: tuple[str, ...]
    before: dict[str, Any]
    after: dict[str, Any]
    after_unknown: dict[str, Any]
    before_sensitive: dict[str, Any]
    after_sensitive: dict[str, Any]
    action_reason: str
    replace_paths: tuple[tuple[str, ...], ...]

    # -- action semantics -------------------------------------------------

    @property
    def is_no_op(self) -> bool:
        return self.actions == ("no-op",)

    @property
    def is_create(self) -> bool:
        return self.actions == ("create",)

    @property
    def is_update(self) -> bool:
        return self.actions == ("update",)

    @property
    def is_delete(self) -> bool:
        return self.actions == ("delete",)

    @property
    def is_read(self) -> bool:
        return self.actions == ("read",)

    @property
    def is_replace(self) -> bool:
        return set(self.actions) == {"create", "delete"}

    @property
    def is_create_before_destroy(self) -> bool:
        """True only for a replacement that creates the new resource first."""
        return self.actions == ("create", "delete")

    @property
    def destroys_data(self) -> bool:
        """True when the existing object goes away, by deletion or replacement."""
        return self.is_delete or self.is_replace

    @property
    def summary(self) -> str:
        if self.is_replace:
            order = "create-then-destroy" if self.is_create_before_destroy else "destroy-then-create"
            return f"replace ({order})"
        return "+".join(self.actions)

    # -- attribute access -------------------------------------------------

    def value(self, key: str, default: Any = None) -> Any:
        """Planned value of an attribute, or ``default`` if absent or unknown."""
        return self.after.get(key, default)

    def prior(self, key: str, default: Any = None) -> Any:
        """Value the attribute had before this change."""
        return self.before.get(key, default)

    def is_unknown(self, key: str) -> bool:
        """True when Terraform cannot predict this attribute until apply."""
        marker = self.after_unknown.get(key)
        if marker is True:
            return True
        # A list/dict marker means some nested part is unknown.
        if isinstance(marker, (list, dict)) and marker:
            return True
        return False

    def unknown_keys(self) -> list[str]:
        return sorted(k for k in self.after_unknown if self.is_unknown(k))

    def is_sensitive(self, key: str) -> bool:
        return bool(self.after_sensitive.get(key)) or bool(self.before_sensitive.get(key))

    def changed(self, key: str) -> bool:
        """True when the attribute's value differs between before and after."""
        if self.is_unknown(key):
            return True
        return self.before.get(key) != self.after.get(key)

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "ResourceChange":
        change = _as_dict(raw.get("change"))
        actions = tuple(str(a) for a in change.get("actions", []) or [])
        raw_paths = change.get("replace_paths") or []
        paths: list[tuple[str, ...]] = []
        for path in raw_paths:
            if isinstance(path, list):
                paths.append(tuple(str(p) for p in path))
        return cls(
            address=str(raw.get("address", "")),
            type=str(raw.get("type", "")),
            name=str(raw.get("name", "")),
            mode=str(raw.get("mode", "managed")),
            provider=str(raw.get("provider_name", "")),
            module_address=str(raw.get("module_address", "")),
            actions=actions,
            before=_as_dict(change.get("before")),
            after=_as_dict(change.get("after")),
            after_unknown=_as_dict(change.get("after_unknown")),
            before_sensitive=_as_dict(change.get("before_sensitive")),
            after_sensitive=_as_dict(change.get("after_sensitive")),
            action_reason=str(raw.get("action_reason", "") or ""),
            replace_paths=tuple(paths),
        )


@dataclass
class Plan:
    """A parsed Terraform plan, exposing only what the analyzers need."""

    path: str
    digest: str
    terraform_version: str
    format_version: str
    resource_changes: list[ResourceChange]
    drift: list[ResourceChange]
    output_changes: dict[str, Any]
    flavour: str = LOCAL_PLAN

    @property
    def effective_changes(self) -> list[ResourceChange]:
        """Resource changes that actually do something."""
        return [rc for rc in self.resource_changes if not rc.is_no_op and not rc.is_read]

    def of_type(self, *types: str) -> list[ResourceChange]:
        wanted = set(types)
        return [rc for rc in self.effective_changes if rc.type in wanted]

    def modules(self) -> list[str]:
        return sorted({rc.module_address for rc in self.effective_changes if rc.module_address})

    def providers(self) -> list[str]:
        return sorted({rc.provider for rc in self.effective_changes if rc.provider})

    @classmethod
    def from_json(cls, data: Any, path: str = "", digest: str = "") -> "Plan":
        if not isinstance(data, dict):
            raise PlanFormatError("plan JSON must be a JSON object at the top level")

        flavour = LOCAL_PLAN
        format_version = str(data.get("format_version", ""))
        if not format_version:
            format_version = str(data.get("plan_format_version", ""))
            if format_version:
                flavour = HCP_PLAN
        if not format_version:
            raise PlanFormatError(
                "missing 'format_version'; this does not look like the output of "
                "'terraform show -json <planfile>', nor an HCP Terraform redacted plan"
            )
        major = format_version.split(".", 1)[0]
        if major.isdigit() and int(major) != SUPPORTED_FORMAT_MAJOR:
            raise PlanFormatError(
                f"plan format version {format_version} is not supported "
                f"(pyrrho understands {SUPPORTED_FORMAT_MAJOR}.x)"
            )

        if "resource_changes" not in data:
            raise PlanFormatError(
                "no 'resource_changes' key. If you passed the output of "
                "'terraform show -json' with no plan file, that is state, not a plan"
            )


        raw_changes = data.get("resource_changes") or []
        if not isinstance(raw_changes, list):
            raise PlanFormatError("'resource_changes' must be a list")

        raw_drift = data.get("resource_drift") or []
        if not isinstance(raw_drift, list):
            raw_drift = []

        return cls(
            path=path,
            digest=digest,
            terraform_version=str(data.get("terraform_version", "")),
            format_version=format_version,
            resource_changes=[ResourceChange.from_json(rc) for rc in raw_changes],
            drift=[ResourceChange.from_json(rc) for rc in raw_drift],
            output_changes=_as_dict(data.get("output_changes")),
            flavour=flavour,
        )


def load(path: str | Path) -> Plan:
    """Read and parse a plan JSON file, recording its digest for attestation."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except FileNotFoundError as exc:
        raise PlanFormatError(f"plan file not found: {p}") from exc
    except IsADirectoryError as exc:
        raise PlanFormatError(f"expected a file, got a directory: {p}") from exc

    digest = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanFormatError(
            f"{p} is not valid JSON. Generate it with: "
            f"terraform show -json tfplan.binary > plan.json"
        ) from exc

    return Plan.from_json(data, path=str(p), digest=digest)


def loads(text: str, path: str = "<string>") -> Plan:
    """Parse a plan from a JSON string. Used by the tests and the corpus runner."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PlanFormatError(f"{path} is not valid JSON: {exc}") from exc
    return Plan.from_json(data, path=path, digest=digest)
