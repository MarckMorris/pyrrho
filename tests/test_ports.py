"""Tests for port classification.

The interesting cases are ranges, because a range is how a wide grant gets past
a reviewer: "1024-65535" reads as one line and swallows most of the data tier.
"""

from __future__ import annotations

import pytest

from pyrrho import ports


class TestAllPorts:
    @pytest.mark.parametrize("protocol", ["-1", "all", "ALL"])
    def test_the_all_protocols_marker_is_recognised(self, protocol):
        assert ports.is_all_ports(None, None, protocol)

    def test_an_explicit_full_tcp_range_is_all_ports(self):
        assert ports.is_all_ports(0, 65535, "tcp")

    def test_a_normal_range_is_not_all_ports(self):
        assert not ports.is_all_ports(80, 443, "tcp")

    def test_missing_ports_on_a_named_protocol_is_not_all_ports(self):
        assert not ports.is_all_ports(None, None, "tcp")


class TestRanges:
    def test_a_single_port_is_a_one_element_range(self):
        assert list(ports.covered(22, 22)) == [22]

    def test_reversed_bounds_are_normalised(self):
        assert list(ports.covered(25, 22)) == [22, 23, 24, 25]

    def test_missing_bounds_produce_no_range(self):
        assert ports.covered(None, 22) is None
        assert ports.covered(22, None) is None


class TestSensitiveServices:
    def test_a_single_admin_port_is_identified(self):
        assert ports.sensitive_in_range(22, 22, "tcp") == {22: "SSH"}

    def test_a_public_port_is_not_flagged_as_sensitive(self):
        assert ports.sensitive_in_range(443, 443, "tcp") == {}

    def test_a_wide_range_reports_everything_it_covers(self):
        found = ports.sensitive_in_range(1024, 65535, "tcp")
        assert 6379 in found and 27017 in found and 9200 in found
        assert 22 not in found

    def test_all_protocols_reports_every_known_service(self):
        assert ports.sensitive_in_range(None, None, "-1") == ports.ADMIN_AND_DATA

    def test_unbounded_ports_on_a_named_protocol_report_nothing(self):
        assert ports.sensitive_in_range(None, None, "tcp") == {}


class TestDescribe:
    def test_all_protocols_is_spelled_out(self):
        assert ports.describe(0, 0, "-1") == "all ports, all protocols"

    def test_a_full_tcp_range_names_the_protocol(self):
        assert ports.describe(0, 65535, "tcp") == "all tcp ports"

    def test_a_known_service_is_labelled(self):
        assert ports.describe(5432, 5432, "tcp") == "tcp/5432 [PostgreSQL]"

    def test_a_public_port_is_labelled_too(self):
        assert ports.describe(443, 443, "tcp") == "tcp/443 [HTTPS]"

    def test_an_unknown_single_port_has_no_label(self):
        assert ports.describe(8080, 8080, "tcp") == "tcp/8080"

    def test_a_range_is_printed_as_a_range(self):
        assert ports.describe(3000, 4000, "tcp") == "tcp/3000-4000"

    def test_unspecified_ports_say_so(self):
        assert ports.describe(None, None, "icmp") == "icmp (unspecified ports)"


class TestTableSanity:
    def test_the_two_tables_do_not_overlap(self):
        assert not set(ports.ADMIN_AND_DATA) & set(ports.PUBLIC_BY_DESIGN)

    def test_every_port_is_in_range(self):
        for port in list(ports.ADMIN_AND_DATA) + list(ports.PUBLIC_BY_DESIGN):
            assert 0 < port <= 65535
