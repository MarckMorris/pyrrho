"""Shared helpers for building Terraform plan documents in tests.

Tests build plans through these helpers rather than reading corpus files, so a
unit test failure points at one rule rather than at the corpus.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pyrrho import plan as plan_mod

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"


def change(
    address: str,
    type_: str,
    actions: list[str],
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "address": address,
        "mode": "managed",
        "type": type_,
        "name": address.split(".")[-1],
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {
            "actions": actions,
            "before": before,
            "after": after,
            "after_unknown": extra.pop("after_unknown", {}),
            "before_sensitive": extra.pop("before_sensitive", False),
            "after_sensitive": extra.pop("after_sensitive", False),
        },
    }
    if "replace_paths" in extra:
        entry["change"]["replace_paths"] = extra.pop("replace_paths")
    entry.update(extra)
    return entry


def make_plan(changes: list[dict[str, Any]], drift: list[dict[str, Any]] | None = None) -> plan_mod.Plan:
    doc: dict[str, Any] = {
        "format_version": "1.2",
        "terraform_version": "1.9.8",
        "resource_changes": changes,
    }
    if drift:
        doc["resource_drift"] = drift
    return plan_mod.loads(json.dumps(doc), path="test-plan.json")


def rule(
    from_port: int | None,
    to_port: int | None,
    protocol: str,
    cidrs: list[str],
    description: str = "",
) -> dict[str, Any]:
    return {
        "from_port": from_port,
        "to_port": to_port,
        "protocol": protocol,
        "cidr_blocks": cidrs,
        "ipv6_cidr_blocks": [],
        "prefix_list_ids": [],
        "security_groups": [],
        "self": False,
        "description": description,
    }


def group(name: str, ingress: list[dict[str, Any]], egress: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "vpc_id": "vpc-0abc",
        "ingress": ingress,
        "egress": egress or [],
        "tags": {},
    }


def rule_ids(findings: list[Any]) -> set[str]:
    return {f.rule_id for f in findings}


@pytest.fixture
def corpus_dir() -> Path:
    return CORPUS
