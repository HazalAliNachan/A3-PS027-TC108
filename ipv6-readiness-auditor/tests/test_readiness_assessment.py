"""
Unit tests for IPv6 readiness assessment and scoring.
"""

from auditor.readiness_assessment import compute_readiness_assessment


def test_perfect_dual_stack_readiness():
    hosts_data = {
        "example.com": {
            "dns": {"ipv6_addresses": ["2606:2800:220:1:248:1893:25c8:1946"], "ipv4_addresses": ["93.184.216.34"]},
            "v6_tcp": {"success": True},
            "v6_tls": {"success": True},
        },
        "cdn.example.com": {
            "dns": {"ipv6_addresses": ["2606:4700::1"], "ipv4_addresses": ["104.16.1.1"]},
            "v6_tcp": {"success": True},
            "v6_tls": {"success": True},
        }
    }
    env = {"ipv6_capable": True}
    res = compute_readiness_assessment("example.com", hosts_data, env)

    assert res["overall_category"] == "IPv6 connectivity verified for tested endpoints"
    assert res["overall_score"] == 100.0
    assert res["main_domain"]["has_aaaa"] is True
    assert res["dependencies"]["with_aaaa"] == 1


def test_partial_readiness():
    hosts_data = {
        "example.com": {
            "dns": {"ipv6_addresses": ["2606:2800::1"], "ipv4_addresses": ["93.184.216.34"]},
            "v6_tcp": {"success": True},
        },
        "cdn.example.com": {
            "dns": {"ipv6_addresses": ["2606:4700::1"], "ipv4_addresses": ["104.16.1.1"]},
            "v6_tcp": {"success": True},
        },
        "analytics.legacy.com": {
            "dns": {"ipv6_addresses": [], "ipv4_addresses": ["198.51.100.1"]},
            "v6_tcp": {"success": False},
        }
    }
    env = {"ipv6_capable": True}
    res = compute_readiness_assessment("example.com", hosts_data, env)

    assert res["overall_category"] == "Partial IPv6 readiness"
    assert 50.0 < res["overall_score"] < 100.0
    assert res["dependencies"]["with_aaaa"] == 1
    assert res["dependencies"]["ipv4_only"] == 1


def test_ipv4_only_main_domain():
    hosts_data = {
        "ipv4only.com": {
            "dns": {"ipv6_addresses": [], "ipv4_addresses": ["198.51.100.1"]},
            "v6_tcp": {},
        }
    }
    env = {"ipv6_capable": True}
    res = compute_readiness_assessment("ipv4only.com", hosts_data, env)

    assert res["overall_category"] == "IPv6 compatibility concerns detected"
    assert res["main_domain"]["has_aaaa"] is False
    assert res["overall_score"] == 0.0
