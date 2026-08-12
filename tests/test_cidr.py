"""Tests for CIDR containment and widening, which most rules depend on."""

from __future__ import annotations

import pytest

from pyrrho import cidr


def net(text: str):
    parsed = cidr.parse(text)
    assert parsed is not None, text
    return parsed


class TestParsing:
    def test_parses_a_normal_cidr(self):
        assert str(net("10.0.0.0/8")) == "10.0.0.0/8"

    def test_parses_a_bare_address_as_a_host_route(self):
        assert str(net("203.0.113.5")) == "203.0.113.5/32"

    def test_accepts_host_bits_set(self):
        # Terraform plans carry operator-written strings; 10.0.0.5/8 is common
        # and must not raise.
        assert str(net("10.0.0.5/8")) == "10.0.0.0/8"

    @pytest.mark.parametrize("bad", ["", "not-a-cidr", "10.0.0.0/33", "999.0.0.1", None])
    def test_rejects_junk_without_raising(self, bad):
        assert cidr.parse(bad) is None

    def test_parse_all_skips_junk_and_non_strings(self):
        result = cidr.parse_all(["10.0.0.0/8", "garbage", 42, None, "::/0"])
        assert [str(n) for n in result] == ["10.0.0.0/8", "::/0"]

    def test_parse_all_handles_none(self):
        assert cidr.parse_all(None) == []


class TestClassification:
    def test_ipv4_default_route_is_world(self):
        assert cidr.is_world(net("0.0.0.0/0"))

    def test_ipv6_default_route_is_world(self):
        assert cidr.is_world(net("::/0"))

    def test_a_slash_24_is_not_world(self):
        assert not cidr.is_world(net("203.0.113.0/24"))

    @pytest.mark.parametrize("private", ["10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "127.0.0.1/32"])
    def test_private_space_is_not_public(self, private):
        assert not cidr.is_public(net(private))

    def test_public_space_is_public(self):
        assert cidr.is_public(net("45.33.32.0/24"))

    @pytest.mark.parametrize(
        "documentation", ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
    )
    def test_rfc5737_documentation_ranges_are_not_public(self, documentation):
        """Deliberate, and worth recording because it surprises people.

        The three ranges reserved by RFC 5737 for documentation are in the IANA
        special-purpose registry, so ``ipaddress`` reports them as private and
        pyrrho does not treat them as internet-facing. That is correct: they are
        not globally routable. It also means example HCL copied out of a blog
        post will not, by itself, trip an exposure rule.
        """
        assert not cidr.is_public(net(documentation))

    def test_world_counts_as_public(self):
        assert cidr.is_public(net("0.0.0.0/0"))

    def test_a_public_slash_8_is_broad(self):
        assert cidr.is_broad(net("198.0.0.0/8"))

    def test_a_public_slash_24_is_not_broad(self):
        assert not cidr.is_broad(net("45.33.32.0/24"))

    def test_a_private_slash_8_is_not_broad(self):
        # Wide, but not reachable from outside; the rule is about public reach.
        assert not cidr.is_broad(net("10.0.0.0/8"))


class TestWidening:
    def test_a_subnet_of_an_existing_allowance_is_not_new(self):
        before = [net("10.0.0.0/8")]
        after = [net("10.1.2.0/24")]
        assert cidr.widened(before, after) == []

    def test_a_supernet_of_an_existing_allowance_is_new(self):
        before = [net("203.0.113.5/32")]
        after = [net("203.0.0.0/8")]
        assert [str(n) for n in cidr.widened(before, after)] == ["203.0.0.0/8"]

    def test_nothing_before_means_everything_is_new(self):
        assert len(cidr.widened([], [net("0.0.0.0/0")])) == 1

    def test_identical_ranges_are_not_a_widening(self):
        same = [net("0.0.0.0/0")]
        assert cidr.widened(same, list(same)) == []

    def test_address_families_do_not_mask_each_other(self):
        # An IPv4 default route must not be treated as covering ::/0.
        before = [net("0.0.0.0/0")]
        after = [net("::/0")]
        assert [str(n) for n in cidr.widened(before, after)] == ["::/0"]

    def test_narrowing_produces_nothing(self):
        before = [net("0.0.0.0/0")]
        after = [net("10.20.0.0/16")]
        assert cidr.widened(before, after) == []


class TestWideningFactor:
    def test_growth_is_measured(self):
        factor = cidr.widening_factor([net("198.51.100.0/24")], [net("198.0.0.0/8")])
        assert factor == pytest.approx(65536.0)

    def test_no_growth_is_one(self):
        assert cidr.widening_factor([net("0.0.0.0/0")], [net("10.0.0.0/8")]) == 1.0

    def test_growth_from_nothing_is_unbounded(self):
        assert cidr.widening_factor([], [net("0.0.0.0/0")]) == float("inf")


class TestDescribe:
    def test_world_is_spelled_out(self):
        assert "entire internet" in cidr.describe(net("0.0.0.0/0"))

    def test_broad_blocks_report_their_size(self):
        assert "16,777,216" in cidr.describe(net("198.51.0.0/8"))

    def test_narrow_blocks_are_printed_plainly(self):
        assert cidr.describe(net("203.0.113.0/24")) == "203.0.113.0/24"
