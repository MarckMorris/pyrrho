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
    """True for 0.0.0.0/0 and ::/0: the entire internet, in one block."""
    return net.prefixlen == 0


def covers_internet(nets: Iterable[IPNetwork]) -> bool:
    """True when the blocks *together* cover the whole address space.

    ``0.0.0.0/1`` and ``128.0.0.0/1`` are the entire internet written as two
    halves. So are four /2s, and so is a list of 256 /8s. Any check that tests
    each block for ``prefixlen == 0`` sees two ordinary-looking CIDRs and lets
    them through, which makes it the cheapest way to defeat a scanner: the rule
    reads as scoped in review and admits everything at runtime.

    Address families are counted separately, because covering all of IPv4 says
    nothing about IPv6 and vice versa.
    """
    by_version: dict[int, list[IPNetwork]] = {}
    for net in nets:
        by_version.setdefault(net.version, []).append(net)

    for version, group in by_version.items():
        try:
            collapsed = list(ipaddress.collapse_addresses(group))  # type: ignore[arg-type]
        except (TypeError, ValueError):  # pragma: no cover - mixed families
            continue
        total = sum(n.num_addresses for n in collapsed)
        if total >= (2 ** (32 if version == 4 else 128)):
            return True
    return False


def reach(nets: Iterable[IPNetwork]) -> str:
    """How far the blocks reach, as one of three words.

    ``internet``  the whole address space, in one block or assembled from parts
    ``broad``     public space too wide to enumerate who is inside it
    ``narrow``    a specific public range, or private space only
    """
    materialised = list(nets)
    if not materialised:
        return "narrow"
    if any(is_world(n) for n in materialised) or covers_internet(materialised):
        return "internet"
    if any(is_broad(n) for n in materialised):
        return "broad"
    return "narrow"


# Blocks that are not globally routable, from the IANA special-purpose address
# registries. This list exists rather than a call to `ipaddress.is_private`
# because that property's meaning *changed between Python releases*: on 3.10
# `ip_network("0.0.0.0/1").is_private` is True, and on 3.11 and later it is
# False. A rule admitting half the internet therefore reported nothing on one
# interpreter and HIGH on another, which is not a defect a security tool is
# allowed to have. Reachability is decided here, by this project, on every
# version.
NOT_GLOBALLY_ROUTABLE_V4: tuple[str, ...] = (
    "0.0.0.0/8",           # "this network"
    "10.0.0.0/8",          # RFC 1918
    "100.64.0.0/10",       # RFC 6598 carrier-grade NAT
    "127.0.0.0/8",         # loopback
    "169.254.0.0/16",      # link-local
    "172.16.0.0/12",       # RFC 1918
    "192.0.0.0/24",        # IETF protocol assignments
    "192.0.2.0/24",        # RFC 5737 TEST-NET-1
    "192.88.99.0/24",      # deprecated 6to4 relay anycast
    "192.168.0.0/16",      # RFC 1918
    "198.18.0.0/15",       # RFC 2544 benchmarking
    "198.51.100.0/24",     # RFC 5737 TEST-NET-2
    "203.0.113.0/24",      # RFC 5737 TEST-NET-3
    "224.0.0.0/4",         # multicast
    "240.0.0.0/4",         # reserved
)

NOT_GLOBALLY_ROUTABLE_V6: tuple[str, ...] = (
    "::/128",              # unspecified
    "::1/128",             # loopback
    "::ffff:0:0/96",       # IPv4-mapped
    "64:ff9b:1::/48",      # local-use NAT64
    "100::/64",            # discard-only
    "2001:db8::/32",       # documentation
    "fc00::/7",            # unique local
    "fe80::/10",           # link-local
    "ff00::/8",            # multicast
)

_RESERVED: dict[int, tuple[IPNetwork, ...]] = {
    4: tuple(ipaddress.ip_network(c) for c in NOT_GLOBALLY_ROUTABLE_V4),
    6: tuple(ipaddress.ip_network(c) for c in NOT_GLOBALLY_ROUTABLE_V6),
}


def is_public(net: IPNetwork) -> bool:
    """True when the block contains at least one globally routable address.

    Note the "at least one". A block is treated as public unless it sits
    entirely inside reserved space, so ``0.0.0.0/1`` is public: it is a
    supernet of some private ranges, and it also admits most of the internet.
    Judging a supernet by the reserved ranges it happens to contain is exactly
    the mistake that made this version-dependent.
    """
    for reserved in _RESERVED.get(net.version, ()):
        if net.subnet_of(reserved):  # type: ignore[arg-type]
            return False
    return True


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
