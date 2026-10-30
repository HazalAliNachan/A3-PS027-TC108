"""
Failure Stage Classification Engine.
Analyzes test results across DNS, TCP, TLS, HTTP, and Browser stages,
categorizing failures transparently with concrete evidence and actionable recommendations.
"""

from typing import Dict, Any, List, Optional


def classify_host_stage(
    hostname: str,
    dns_result: Dict[str, Any],
    v4_tcp: Optional[Dict[str, Any]],
    v6_tcp: Optional[Dict[str, Any]],
    v4_tls: Optional[Dict[str, Any]],
    v6_tls: Optional[Dict[str, Any]],
    v4_http: Optional[Dict[str, Any]],
    v6_http: Optional[Dict[str, Any]],
    env_capabilities: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Evaluates stage-wise test outcomes for a single host and returns structured findings.
    """
    findings: List[Dict[str, Any]] = []

    # 1. DNS Analysis Stage
    if dns_result.get("ipv4_status") == "DNS resolution error" and dns_result.get("ipv6_status") == "DNS resolution error":
        findings.append({
            "hostname": hostname,
            "stage": "DNS Resolution",
            "address_family": "Dual-Stack",
            "failure_category": "DNS Resolution Failure",
            "observed_failure": "Hostname failed to resolve any A or AAAA records.",
            "evidence": f"IPv4 DNS error: {dns_result.get('error_ipv4')}; IPv6 DNS error: {dns_result.get('error_ipv6')}",
            "confidence": "High",
            "recommendation": "Verify domain registration, authoritative nameserver status, and public DNS delegation."
        })
        return findings  # Cannot proceed to TCP/TLS/HTTP if host cannot be resolved

    # IPv6 DNS Analysis
    v6_status = dns_result.get("ipv6_status")
    if v6_status == "IPv6 DNS unavailable":
        findings.append({
            "hostname": hostname,
            "stage": "DNS Resolution",
            "address_family": "IPv6",
            "failure_category": "Missing IPv6 AAAA Record",
            "observed_failure": "Host has valid IPv4 DNS (A) but lacks IPv6 DNS (AAAA) records.",
            "evidence": f"A records: {dns_result.get('ipv4_addresses')}; AAAA records: None (NODATA)",
            "confidence": "High",
            "recommendation": "Publish authoritative AAAA DNS records pointing to the IPv6 address of the web server or CDN edge."
        })

    # 2. Environment Limitation Check for IPv6 Live Tests
    if not env_capabilities.get("ipv6_capable", False):
        if dns_result.get("ipv6_addresses"):
            findings.append({
                "hostname": hostname,
                "stage": "Testing Environment Limitation",
                "address_family": "IPv6",
                "failure_category": "Environment Limitation",
                "observed_failure": "Auditor host has no default IPv6 internet route. IPv6 TCP/TLS/HTTP tests could not be executed.",
                "evidence": f"Target has valid AAAA ({dns_result.get('ipv6_addresses')}), but local host lacks outbound IPv6.",
                "confidence": "High",
                "recommendation": "Execute the audit from an IPv6-enabled network or dual-stack cloud instance to measure live IPv6 traffic."
            })

    # 3. IPv6 TCP Stage (only if target had AAAA and host was capable)
    if v6_tcp and not v6_tcp.get("is_env_limitation", False):
        if not v6_tcp.get("success", False):
            err_cat = v6_tcp.get("error_category", "TCP Connection Error")
            err_detail = v6_tcp.get("error_detail", "Connection failed")
            findings.append({
                "hostname": hostname,
                "stage": "TCP Connection",
                "address_family": "IPv6",
                "failure_category": err_cat,
                "observed_failure": f"IPv6 TCP handshake failed to {v6_tcp.get('ip')}:{v6_tcp.get('port')}",
                "evidence": err_detail,
                "confidence": "High",
                "recommendation": "Check border firewall rules, security groups, and web server listeners for IPv6 port binding."
            })

    # 4. IPv6 TLS Handshake Stage
    if v6_tls and not v6_tls.get("is_env_limitation", False):
        if not v6_tls.get("success", False):
            err_cat = v6_tls.get("error_category", "TLS Error")
            err_detail = v6_tls.get("error_detail", "TLS setup failed")
            findings.append({
                "hostname": hostname,
                "stage": "TLS Handshake",
                "address_family": "IPv6",
                "failure_category": err_cat,
                "observed_failure": f"TLS handshake failed over IPv6 to {hostname}",
                "evidence": err_detail,
                "confidence": "High",
                "recommendation": "Ensure TLS certificates cover the hostname, intermediate CAs are chained, and SNI is configured on IPv6 virtual hosts."
            })

    # 5. IPv6 HTTP Response Stage
    if v6_http and not v6_http.get("is_env_limitation", False):
        if v6_http.get("status_code"):
            code = v6_http["status_code"]
            if code >= 500:
                findings.append({
                    "hostname": hostname,
                    "stage": "HTTP Response",
                    "address_family": "IPv6",
                    "failure_category": "HTTP Server Error",
                    "observed_failure": f"HTTP {code} {v6_http.get('reason')} received over IPv6.",
                    "evidence": f"Server returned error code {code}",
                    "confidence": "Medium",
                    "recommendation": "Check application server logs, reverse proxy routing, and upstream backend health."
                })
            elif code in (401, 403):
                findings.append({
                    "hostname": hostname,
                    "stage": "HTTP Response",
                    "address_family": "IPv6",
                    "failure_category": "HTTP Access Restriction",
                    "observed_failure": f"HTTP {code} {v6_http.get('reason')} received (Access Denied / Forbidden).",
                    "evidence": f"Request blocked or restricted with HTTP {code}. (Note: This is an application/WAF policy, not necessarily an IPv6 network failure).",
                    "confidence": "Medium",
                    "recommendation": "Inspect Web Application Firewall (WAF) or access rules that may filter automated requests."
                })

    # 6. IPv4 Parity Checks
    if v4_tcp and not v4_tcp.get("success", False):
        findings.append({
            "hostname": hostname,
            "stage": "TCP Connection",
            "address_family": "IPv4",
            "failure_category": v4_tcp.get("error_category", "TCP Failure"),
            "observed_failure": f"IPv4 TCP connection failed to {v4_tcp.get('ip')}:{v4_tcp.get('port')}",
            "evidence": v4_tcp.get("error_detail", "Unknown error"),
            "confidence": "High",
            "recommendation": "Check IPv4 server availability and network routing."
        })

    return findings


def classify_resource_failures(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Examines browser-discovered resource failures and flags browser-level issues.
    """
    findings = []
    for res in resources:
        if not res.get("success", True) and res.get("failure_message"):
            msg = res.get("failure_message", "")
            findings.append({
                "hostname": res.get("hostname", ""),
                "resource_url": res.get("url", ""),
                "stage": "Browser Resource Loading",
                "address_family": "Application / Browser",
                "failure_category": "Browser Asset Load Failure",
                "observed_failure": f"Browser failed to fetch resource: {res.get('resource_type')}",
                "evidence": msg,
                "confidence": "Medium",
                "recommendation": "Check if resource was blocked by browser CORS policy, ad-blocker, or returned a 404/500."
            })
    return findings
