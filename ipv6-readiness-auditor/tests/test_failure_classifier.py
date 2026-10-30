"""
Unit tests for the failure classification engine.
"""

from auditor.failure_classifier import classify_host_stage, classify_resource_failures


def test_classify_missing_aaaa():
    dns_res = {
        "ipv4_status": "IPv4 DNS available",
        "ipv6_status": "IPv6 DNS unavailable",
        "ipv4_addresses": ["93.184.216.34"],
        "ipv6_addresses": [],
    }
    env = {"ipv6_capable": True}
    findings = classify_host_stage("cdn.example.com", dns_res, None, None, None, None, None, None, env)

    assert len(findings) == 1
    f = findings[0]
    assert f["stage"] == "DNS Resolution"
    assert f["failure_category"] == "Missing IPv6 AAAA Record"
    assert f["confidence"] == "High"
    assert "AAAA" in f["recommendation"]


def test_classify_environment_limitation():
    dns_res = {
        "ipv4_status": "IPv4 DNS available",
        "ipv6_status": "IPv6 DNS available",
        "ipv4_addresses": ["93.184.216.34"],
        "ipv6_addresses": ["2606:2800:220:1:248:1893:25c8:1946"],
    }
    # Local auditor lacks IPv6 default route
    env = {"ipv6_capable": False}
    findings = classify_host_stage("example.com", dns_res, None, None, None, None, None, None, env)

    assert any(f["stage"] == "Testing Environment Limitation" for f in findings)
    env_finding = next(f for f in findings if f["stage"] == "Testing Environment Limitation")
    assert "IPv6" in env_finding["observed_failure"]
    assert "route" in env_finding["observed_failure"].lower()


def test_classify_tcp_failure():
    dns_res = {
        "ipv4_status": "IPv4 DNS available",
        "ipv6_status": "IPv6 DNS available",
        "ipv4_addresses": ["93.184.216.34"],
        "ipv6_addresses": ["2606:2800:220:1:248:1893:25c8:1946"],
    }
    env = {"ipv6_capable": True}
    v6_tcp = {
        "success": False,
        "is_env_limitation": False,
        "ip": "2606:2800:220:1:248:1893:25c8:1946",
        "port": 443,
        "error_category": "Connection Refused",
        "error_detail": "Port 443 actively refused connection",
    }
    findings = classify_host_stage("example.com", dns_res, None, v6_tcp, None, None, None, None, env)

    assert any(f["stage"] == "TCP Connection" for f in findings)
    tcp_finding = next(f for f in findings if f["stage"] == "TCP Connection")
    assert tcp_finding["failure_category"] == "Connection Refused"


def test_classify_browser_resource_failure():
    resources = [
        {
            "url": "https://example.com/asset.js",
            "hostname": "example.com",
            "resource_type": "script",
            "success": False,
            "failure_message": "net::ERR_BLOCKED_BY_CLIENT"
        }
    ]
    findings = classify_resource_failures(resources)
    assert len(findings) == 1
    assert findings[0]["stage"] == "Browser Resource Loading"
    assert "ERR_BLOCKED_BY_CLIENT" in findings[0]["evidence"]
