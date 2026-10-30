"""
Audit Orchestrator Module.
Coordinates the end-to-end execution of the IPv6 readiness audit workflow:
URL validation, environment baseline check, browser resource discovery,
stage-wise DNS/TCP/TLS/HTTP testing, failure classification, and assessment.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable
from urllib.parse import urlparse

from .url_validation import validate_and_normalize_url
from .network_checker import detect_environment_capabilities, check_tcp_connection
from .dns_checker import check_dns
from .tls_checker import test_tls_connection
from .http_checker import test_http_endpoint
from .browser_discovery import discover_resources
from .failure_classifier import classify_host_stage, classify_resource_failures
from .readiness_assessment import compute_readiness_assessment
from .dependency_graph import generate_dependency_graph


def run_full_audit(
    url: str,
    progress_callback: Optional[Callable[[int, str], None]] = None
) -> Dict[str, Any]:
    """
    Executes the comprehensive IPv6 and dependency readiness audit.
    """
    def update_progress(pct: int, msg: str):
        if progress_callback:
            progress_callback(pct, msg)

    start_time_utc = datetime.now(timezone.utc).isoformat()

    # 1. Input Validation & SSRF Defense
    update_progress(5, "Validating URL and verifying security restrictions...")
    is_valid, norm_url, err_msg, target_host, target_port, target_scheme = validate_and_normalize_url(url)
    if not is_valid:
        return {
            "success": False,
            "error": err_msg or "Invalid URL provided.",
            "target_url": url,
            "audit_timestamp_utc": start_time_utc
        }

    # 2. Environment Capability Baseline Check
    update_progress(15, "Checking auditor host IPv4 and IPv6 network capabilities...")
    env_capabilities = detect_environment_capabilities()

    # 3. Browser-based Resource Discovery
    update_progress(25, f"Discovering page dependencies for {target_host}...")
    discovery = discover_resources(
        norm_url,
        timeout_ms=15000,
        status_callback=lambda msg: update_progress(35, msg)
    )

    resources = discovery.get("resources", [])
    unique_hosts = discovery.get("unique_hosts", [])
    if target_host not in unique_hosts:
        unique_hosts.insert(0, target_host)

    # 4. Stage-Wise Network Testing for Each Discovered Host
    hosts_results: Dict[str, Dict[str, Any]] = {}
    total_hosts = len(unique_hosts)

    for idx, host in enumerate(unique_hosts):
        step_pct = 40 + int(((idx + 1) / total_hosts) * 40)
        update_progress(step_pct, f"Auditing stage-wise connectivity for {host} ({idx + 1}/{total_hosts})...")

        # Stage A: DNS Analysis
        dns_res = check_dns(host)

        # Stage B: TCP & TLS & HTTP IPv4
        v4_tcp = None
        v4_tls = None
        v4_http = None
        if dns_res.get("ipv4_addresses"):
            v4_ip = dns_res["ipv4_addresses"][0]
            v4_tcp = check_tcp_connection(v4_ip, target_port, is_ipv6=False)
            if v4_tcp.get("success"):
                if target_scheme == "https" or target_port == 443:
                    v4_tls = test_tls_connection(v4_ip, host, target_port, is_ipv6=False)
                v4_http = test_http_endpoint(v4_ip, host, target_port, target_scheme, "/", is_ipv6=False)

        # Stage C: TCP & TLS & HTTP IPv6
        v6_tcp = None
        v6_tls = None
        v6_http = None
        if dns_res.get("ipv6_addresses"):
            v6_ip = dns_res["ipv6_addresses"][0]
            v6_tcp = check_tcp_connection(
                v6_ip, target_port, is_ipv6=True,
                env_v6_capable=env_capabilities.get("ipv6_capable", False)
            )
            if v6_tcp.get("success"):
                if target_scheme == "https" or target_port == 443:
                    v6_tls = test_tls_connection(
                        v6_ip, host, target_port, is_ipv6=True,
                        env_v6_capable=env_capabilities.get("ipv6_capable", False)
                    )
                v6_http = test_http_endpoint(
                    v6_ip, host, target_port, target_scheme, "/", is_ipv6=True,
                    env_v6_capable=env_capabilities.get("ipv6_capable", False)
                )

        hosts_results[host] = {
            "hostname": host,
            "dns": dns_res,
            "v4_tcp": v4_tcp or {},
            "v4_tls": v4_tls or {},
            "v4_http": v4_http or {},
            "v6_tcp": v6_tcp or {},
            "v6_tls": v6_tls or {},
            "v6_http": v6_http or {},
        }

    # 5. Failure Stage Classification
    update_progress(85, "Analyzing connection failure stages and root causes...")
    all_findings: List[Dict[str, Any]] = []

    for host, h_data in hosts_results.items():
        host_findings = classify_host_stage(
            host,
            h_data["dns"],
            h_data["v4_tcp"],
            h_data["v6_tcp"],
            h_data["v4_tls"],
            h_data["v6_tls"],
            h_data["v4_http"],
            h_data["v6_http"],
            env_capabilities
        )
        all_findings.extend(host_findings)

    resource_findings = classify_resource_failures(resources)
    all_findings.extend(resource_findings)

    # 6. IPv6 Readiness Assessment
    update_progress(92, "Synthesizing IPv6 readiness assessment...")
    assessment = compute_readiness_assessment(target_host, hosts_results, env_capabilities)

    # 7. Generate Dependency Graph
    update_progress(96, "Generating dependency ecosystem graph...")
    graph_fig = generate_dependency_graph(target_host, hosts_results, resources)

    update_progress(100, "Audit completed successfully.")

    return {
        "success": True,
        "target_url": norm_url,
        "target_host": target_host,
        "target_port": target_port,
        "target_scheme": target_scheme,
        "audit_timestamp_utc": start_time_utc,
        "environment_capabilities": env_capabilities,
        "discovery_summary": {
            "method": discovery.get("discovery_method"),
            "page_title": discovery.get("page_title"),
            "browser_error": discovery.get("browser_error"),
            "total_resources": len(resources),
            "total_requests": discovery.get("total_requests", len(resources)),
            "unique_hosts_count": len(unique_hosts),
        },
        "resources": resources,
        "hosts": hosts_results,
        "findings": all_findings,
        "assessment": assessment,
        "graph_figure": graph_fig,
    }
