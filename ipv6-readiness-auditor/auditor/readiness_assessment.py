"""
IPv6 Readiness Assessment Engine.
Computes objective readiness classifications and transparent scoring
for both the primary domain and all discovered dependencies.
"""

from typing import Dict, Any, List


def compute_readiness_assessment(
    target_host: str,
    hosts_data: Dict[str, Dict[str, Any]],
    env_capabilities: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates the readiness metrics across all audited hosts.

    Returns:
      - overall_category: str
      - overall_score: float (0.0 to 100.0)
      - main_domain_status: Dict
      - dependencies_summary: Dict
      - scoring_breakdown: Dict
      - environment_notice: Optional[str]
    """
    env_v6 = env_capabilities.get("ipv6_capable", False)

    total_hosts = len(hosts_data)
    main_host_data = hosts_data.get(target_host, {})
    dep_hosts = {h: d for h, d in hosts_data.items() if h != target_host}

    # 1. Main domain evaluation
    main_dns = main_host_data.get("dns", {})
    main_has_aaaa = bool(main_dns.get("ipv6_addresses"))
    main_v6_tcp = main_host_data.get("v6_tcp", {})
    main_v6_tls = main_host_data.get("v6_tls", {})
    main_v6_http = main_host_data.get("v6_http", {})

    main_v6_connected = main_v6_tcp.get("success", False) or main_v6_tls.get("success", False) or main_v6_http.get("success", False)

    # 2. Dependencies evaluation
    dep_count = len(dep_hosts)
    dep_with_aaaa = 0
    dep_v6_connected = 0
    dep_v4_only = 0
    dep_dns_failed = 0

    for h, data in dep_hosts.items():
        dns_res = data.get("dns", {})
        has_v4 = bool(dns_res.get("ipv4_addresses"))
        has_v6 = bool(dns_res.get("ipv6_addresses"))

        if has_v6:
            dep_with_aaaa += 1
            v6_tcp = data.get("v6_tcp", {})
            v6_tls = data.get("v6_tls", {})
            if v6_tcp.get("success", False) or v6_tls.get("success", False):
                dep_v6_connected += 1
        elif has_v4 and not has_v6:
            dep_v4_only += 1
        else:
            dep_dns_failed += 1

    # 3. Transparent scoring calculation
    # We assign:
    # - Main Host AAAA DNS: 25 points
    # - Main Host IPv6 Live Connectivity: 25 points (or awarded if DNS confirmed and environment limited)
    # - Dependency AAAA Adoption Rate: 25 points
    # - Dependency Live IPv6 Connectivity Rate: 25 points (or awarded if DNS confirmed and environment limited)
    score_main_dns = 25.0 if main_has_aaaa else 0.0

    if env_v6:
        score_main_conn = 25.0 if main_v6_connected else 0.0
    else:
        # If environment cannot test IPv6 outbound, live connection points track DNS presence
        score_main_conn = 25.0 if main_has_aaaa else 0.0

    if dep_count > 0:
        dep_aaaa_ratio = dep_with_aaaa / dep_count
        score_dep_dns = round(dep_aaaa_ratio * 25.0, 2)

        if env_v6:
            dep_conn_ratio = dep_v6_connected / dep_count
            score_dep_conn = round(dep_conn_ratio * 25.0, 2)
        else:
            score_dep_conn = round(dep_aaaa_ratio * 25.0, 2)
    else:
        # No third-party dependencies, main domain carries full weight
        score_dep_dns = 25.0 if main_has_aaaa else 0.0
        score_dep_conn = score_main_conn

    total_score = round(score_main_dns + score_main_conn + score_dep_dns + score_dep_conn, 1)

    # 4. Overall Category Determination
    if total_hosts == 0:
        overall_cat = "Insufficient evidence to determine readiness"
    elif not main_has_aaaa:
        overall_cat = "IPv6 compatibility concerns detected"
    elif env_v6 and main_v6_connected and (dep_count == 0 or dep_with_aaaa == dep_count):
        overall_cat = "IPv6 connectivity verified for tested endpoints"
    elif not env_v6 and main_has_aaaa and (dep_count == 0 or dep_with_aaaa == dep_count):
        overall_cat = "IPv6 DNS verified (Live tests inconclusive due to auditor environment)"
    elif main_has_aaaa and dep_with_aaaa > 0:
        overall_cat = "Partial IPv6 readiness"
    elif main_has_aaaa and dep_count > 0 and dep_with_aaaa == 0:
        overall_cat = "IPv6 compatibility concerns detected"
    else:
        overall_cat = "IPv6 testing inconclusive"

    env_notice = None
    if not env_v6:
        env_notice = (
            "Auditor Host Environment Notice: The testing machine does not have an active outbound IPv6 route. "
            "DNS AAAA records were queried and verified via dual-stack DNS, but live IPv6 TCP/TLS handshakes were "
            "restricted by host environment limitations."
        )

    return {
        "overall_category": overall_cat,
        "overall_score": total_score,
        "is_environment_limited": not env_v6,
        "environment_notice": env_notice,
        "main_domain": {
            "hostname": target_host,
            "has_aaaa": main_has_aaaa,
            "ipv6_addresses": main_dns.get("ipv6_addresses", []),
            "ipv4_addresses": main_dns.get("ipv4_addresses", []),
            "live_connected": main_v6_connected,
            "status": "Ready (Dual-Stack)" if main_has_aaaa else "IPv4-Only (Missing AAAA)",
        },
        "dependencies": {
            "total_dependencies": dep_count,
            "with_aaaa": dep_with_aaaa,
            "ipv4_only": dep_v4_only,
            "dns_failed": dep_dns_failed,
            "live_connected": dep_v6_connected,
            "aaaa_adoption_rate_percent": round((dep_with_aaaa / dep_count * 100), 1) if dep_count > 0 else 100.0,
        },
        "scoring_breakdown": {
            "main_dns_score": score_main_dns,
            "main_connectivity_score": score_main_conn,
            "dep_dns_score": score_dep_dns,
            "dep_connectivity_score": score_dep_conn,
            "formula": "Readiness Score = Main_DNS (25%) + Main_Conn (25%) + Dep_DNS (25%) + Dep_Conn (25%)",
        }
    }
