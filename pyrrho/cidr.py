"""CIDR reasoning, using only the standard library.

Most Terraform scanners stop at a string comparison against ``0.0.0.0/0``. That
misses the change that actually causes incidents: a rule that was scoped to a
peer office range being widened to a whole /8, or an IPv6 ``::/0`` slipped in
beside an unchanged and innocent-looking IPv4 block. This module exists so the
network analyzer can reason about containment and widening rather than equality.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Any public block at or wider than this prefix length is treated as a broad
# grant. /16 is roughly "an entire large enterprise's public allocation": wide
# enough that nobody can enumerate who is inside it.
BROAD_IPV4_PREFIX = 16
BROAD_IPV6_PREFIX = 48


def parse(value: str) -> IPNetwork | None:
    """Parse one CIDR string, tolerating bare addresses. Returns None if invalid.

    Terraform lets a plan carry values that were never validated by the provider
    (an interpolated string, an operator's typo). A parse failure must not crash
    the review, so unusable values are dropped and reported by the caller.
    """
    text = (value or "").strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def parse_all(values: Iterable[str] | None) -> list[IPNetwork]:
    """Parse a list of CIDR strings, silently skipping the unparseable ones."""
    if not values:
        return []
    out: list[IPNetwork] = []
    for value in values:
        if not isinstance(value, str):
            continue
        net = parse(value)
        if net is not None:
            out.append(net)
    return out


def is_world(net: IPNetwork) -> bool:
    """True for 0.0.0.0/0 and ::/0: the entire internet."""
    return net.prefixlen == 0


def is_public(net: IPNetwork) -> bool:
    """True when the block contains addresses reachable from the internet.

    ``ip_network.is_private`` is False for 0.0.0.0/0 even though that block
    *contains* private space, which is the behaviour we want here: a rule that
    admits 0.0.0.0/0 admits the public internet regardless of what else it
    admits.
    """
    if is_world(net):
        return True
    return not (
        net.is_private
        or net.is_loopback
        or net.is_link_local
        or net.is_multicast
        or net.is_reserved
    )


def is_broad(net: IPNetwork) -> bool:
    """True for a public block wide enough that its membership is unknowable."""
    if not is_public(net):
        return False
    limit = BROAD_IPV4_PREFIX if net.version == 4 else BROAD_IPV6_PREFIX
    return net.prefixlen <= limit


def host_count(net: IPNetwork) -> int:
    """Number of addresses the block covers. Used to quantify a widening."""
    return net.num_addresses


def covered_by(net: IPNetwork, others: Iterable[IPNetwork]) -> bool:
    """True when ``net`` is entirely inside at least one of ``others``."""
    for other in others:
        if net.version != other.version:
            continue
        if net.subnet_of(other):  # type: ignore[arg-type]
            return True
    return False


def widened(before: Iterable[IPNetwork], after: Iterable[IPNetwork]) -> list[IPNetwork]:
    """Blocks in ``after`` that are not contained in anything from ``before``.

    This is the useful definition of "the rule got wider". Adding 10.0.1.0/24
    when 10.0.0.0/8 was already allowed is not a widening; replacing
    203.0.113.5/32 with 203.0.0.0/8 is, and by a factor of sixteen million.
    """
    before_list = list(before)
    return [net for net in after if not covered_by(net, before_list)]


def widening_factor(before: Iterable[IPNetwork], after: Iterable[IPNetwork]) -> float:
    """How many times more addresses ``after`` admits than ``before``.

    Returns ``float('inf')`` when the rule went from admitting nothing to
    admitting something, and 1.0 when nothing grew.
    """
    before_total = sum(host_count(n) for n in before)
    after_total = sum(host_count(n) for n in after)
    if after_total <= before_total:
        return 1.0
    if before_total == 0:
        return float("inf")
    return after_total / before_total


def describe(net: IPNetwork) -> str:
    """Short human label used in finding messages and evidence."""
    if is_world(net):
        return f"{net} (the entire internet)"
    if is_broad(net):
        return f"{net} ({host_count(net):,} public addresses)"
    return str(net)
