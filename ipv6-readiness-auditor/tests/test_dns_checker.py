"""
Unit tests for DNS analysis module.
"""

from unittest.mock import patch, MagicMock
import pytest
from auditor.dns_checker import check_dns


def test_dual_stack_dns_success():
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        # Mock A record
        mock_a = MagicMock()
        mock_a.address = "93.184.216.34"

        # Mock AAAA record
        mock_aaaa = MagicMock()
        mock_aaaa.address = "2606:2800:220:1:248:1893:25c8:1946"

        def side_effect(qname, rdtype):
            if rdtype == "A":
                return [mock_a]
            elif rdtype == "AAAA":
                return [mock_aaaa]
            raise Exception("Unknown query")

        mock_resolve.side_effect = side_effect

        res = check_dns("example.com")
        assert res["ipv4_status"] == "IPv4 DNS available"
        assert res["ipv6_status"] == "IPv6 DNS available"
        assert res["ipv4_addresses"] == ["93.184.216.34"]
        assert res["ipv6_addresses"] == ["2606:2800:220:1:248:1893:25c8:1946"]
        assert res["overall_dns_status"] == "Dual-Stack DNS (A + AAAA)"


def test_ipv4_only_dns():
    import dns.resolver

    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_a = MagicMock()
        mock_a.address = "198.51.100.1"

        def side_effect(qname, rdtype):
            if rdtype == "A":
                return [mock_a]
            elif rdtype == "AAAA":
                raise dns.resolver.NoAnswer()
            raise Exception()

        mock_resolve.side_effect = side_effect

        res = check_dns("ipv4only.example.com")
        assert res["ipv4_status"] == "IPv4 DNS available"
        assert res["ipv6_status"] == "IPv6 DNS unavailable"
        assert res["ipv4_addresses"] == ["198.51.100.1"]
        assert res["ipv6_addresses"] == []
        assert res["overall_dns_status"] == "IPv4-Only DNS (A)"


def test_nxdomain_dns():
    import dns.resolver

    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        res = check_dns("this-domain-does-not-exist-12345.org")
        assert res["ipv4_status"] == "DNS resolution error"
        assert res["ipv6_status"] == "DNS resolution error"
        assert "NXDOMAIN" in (res["error_ipv4"] or "")
