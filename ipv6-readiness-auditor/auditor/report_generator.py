"""
Audit Report Generator Module.
Generates comprehensive JSON reports, tabular CSV resource exports,
and standalone styled HTML audit reports suitable for hackathon presentation and archiving.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List
import pandas as pd


def generate_json_report(audit_data: Dict[str, Any]) -> str:
    """
    Serializes full audit data to formatted JSON string.
    """
    return json.dumps(audit_data, indent=2, default=str)


def generate_csv_report(audit_data: Dict[str, Any]) -> str:
    """
    Extracts tabular resource and host records into CSV string format.
    """
    resources = audit_data.get("resources", [])
    hosts_data = audit_data.get("hosts", {})

    rows = []
    for r in resources:
        h = r.get("hostname", "")
        h_info = hosts_data.get(h, {})
        dns_info = h_info.get("dns", {})
        v4_tcp = h_info.get("v4_tcp", {})
        v6_tcp = h_info.get("v6_tcp", {})

        rows.append({
            "Resource URL": r.get("url", ""),
            "Hostname": h,
            "Resource Type": r.get("resource_type", "unknown"),
            "Party Classification": "Third-Party" if r.get("is_third_party") else "First-Party",
            "HTTP Method": r.get("method", "GET"),
            "Browser Status Code": r.get("status_code", "N/A"),
            "Browser Observed": r.get("observed_in_browser", True),
            "Duration (ms)": r.get("duration_ms", 0.0),
            "IPv4 DNS (A)": ", ".join(dns_info.get("ipv4_addresses", [])) or "None",
            "IPv6 DNS (AAAA)": ", ".join(dns_info.get("ipv6_addresses", [])) or "None",
            "IPv4 TCP Handshake": "Success" if v4_tcp.get("success") else v4_tcp.get("error_category", "Untested"),
            "IPv6 TCP Handshake": "Success" if v6_tcp.get("success") else v6_tcp.get("error_category", "Untested"),
        })

    if not rows:
        # Default placeholder row to prevent empty CSV crash
        df = pd.DataFrame(columns=[
            "Resource URL", "Hostname", "Resource Type", "Party Classification",
            "HTTP Method", "Browser Status Code", "Browser Observed", "Duration (ms)",
            "IPv4 DNS (A)", "IPv6 DNS (AAAA)", "IPv4 TCP Handshake", "IPv6 TCP Handshake"
        ])
    else:
        df = pd.DataFrame(rows)

    return df.to_csv(index=False)


def generate_html_report(audit_data: Dict[str, Any]) -> str:
    """
    Builds a standalone, responsive HTML report with modern cybersecurity styling.
    """
    target = audit_data.get("target_url", "N/A")
    target_host = audit_data.get("target_host", "N/A")
    timestamp = audit_data.get("audit_timestamp_utc", datetime.now(timezone.utc).isoformat())
    assessment = audit_data.get("assessment", {})
    score = assessment.get("overall_score", 0.0)
    category = assessment.get("overall_category", "Unknown")
    env = audit_data.get("environment_capabilities", {})
    findings = audit_data.get("findings", [])
    hosts = audit_data.get("hosts", {})
    resources = audit_data.get("resources", [])

    # Score color
    if score >= 80:
        score_badge = f'<span style="background:#059669; color:#fff; padding:6px 14px; border-radius:20px; font-weight:bold;">{score}/100 — {category}</span>'
    elif score >= 50:
        score_badge = f'<span style="background:#d97706; color:#fff; padding:6px 14px; border-radius:20px; font-weight:bold;">{score}/100 — {category}</span>'
    else:
        score_badge = f'<span style="background:#dc2626; color:#fff; padding:6px 14px; border-radius:20px; font-weight:bold;">{score}/100 — {category}</span>'

    findings_rows = ""
    for f in findings:
        conf_color = "#dc2626" if f.get("confidence") == "High" else "#d97706"
        findings_rows += f"""
        <tr>
            <td><strong>{f.get('hostname', 'N/A')}</strong></td>
            <td><span class="badge">{f.get('stage', 'N/A')}</span></td>
            <td>{f.get('observed_failure', 'N/A')}</td>
            <td><small>{f.get('evidence', '')}</small></td>
            <td>{f.get('recommendation', 'N/A')}</td>
        </tr>
        """

    if not findings:
        findings_rows = "<tr><td colspan='5' style='text-align:center;'>No critical IPv6 or connectivity failures detected.</td></tr>"

    hosts_rows = ""
    for h, data in hosts.items():
        dns = data.get("dns", {})
        v4_ips = "<br>".join(dns.get("ipv4_addresses", [])) or "<span style='color:#94a3b8;'>None</span>"
        v6_ips = "<br>".join(dns.get("ipv6_addresses", [])) or "<span style='color:#ef4444;'>No AAAA</span>"
        v4_status = "Ready" if dns.get("ipv4_addresses") else "Error"
        v6_status = "Ready" if dns.get("ipv6_addresses") else "Missing AAAA"
        badge_class = "badge-success" if dns.get("ipv6_addresses") else "badge-warning"

        hosts_rows += f"""
        <tr>
            <td><strong>{h}</strong> {'(Main)' if h == target_host else ''}</td>
            <td><span class="badge {badge_class}">{v6_status}</span></td>
            <td><code>{v4_ips}</code></td>
            <td><code>{v6_ips}</code></td>
            <td>{dns.get('ipv4_lookup_time_ms', 0)} ms / {dns.get('ipv6_lookup_time_ms', 0)} ms</td>
        </tr>
        """

    env_banner = ""
    if assessment.get("is_environment_limited"):
        env_banner = f"""
        <div class="alert alert-warning">
            <strong>Auditor Host Limitation Notice:</strong> {assessment.get('environment_notice')}
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IPv6 Readiness Audit Report - {target_host}</title>
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background: #0f172a;
        color: #e2e8f0;
        margin: 0;
        padding: 30px;
        line-height: 1.6;
    }}
    .container {{
        max-width: 1100px;
        margin: 0 auto;
        background: #1e293b;
        border-radius: 12px;
        padding: 32px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }}
    h1, h2, h3 {{ color: #f8fafc; }}
    .header-box {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 2px solid #334155;
        padding-bottom: 20px;
        margin-bottom: 24px;
    }}
    .summary-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }}
    .card {{
        background: #0f172a;
        padding: 18px;
        border-radius: 8px;
        border: 1px solid #334155;
    }}
    .card-title {{ font-size: 13px; text-transform: uppercase; color: #94a3b8; font-weight: 600; }}
    .card-value {{ font-size: 24px; font-weight: bold; margin-top: 6px; color: #38bdf8; }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 16px 0;
        background: #0f172a;
        border-radius: 8px;
        overflow: hidden;
    }}
    th, td {{
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid #334155;
    }}
    th {{ background: #1e293b; color: #94a3b8; font-size: 13px; text-transform: uppercase; }}
    code {{ background: #334155; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #f1f5f9; }}
    .badge {{
        display: inline-block;
        padding: 4px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
        background: #334155;
        color: #f8fafc;
    }}
    .badge-success {{ background: #065f46; color: #34d399; }}
    .badge-warning {{ background: #78350f; color: #fbbf24; }}
    .alert {{
        padding: 14px 18px;
        border-radius: 8px;
        margin-bottom: 20px;
        font-size: 14px;
    }}
    .alert-warning {{ background: #451a03; border: 1px solid #b45309; color: #fde68a; }}
    .footer {{
        margin-top: 40px;
        padding-top: 20px;
        border-top: 1px solid #334155;
        font-size: 12px;
        color: #94a3b8;
        text-align: center;
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header-box">
        <div>
            <h1>IPv6 Website & Dependency Readiness Audit</h1>
            <p style="color:#94a3b8; margin:4px 0;">Target: <strong>{target}</strong> | Timestamp: {timestamp}</p>
            <p style="color:#64748b; font-size:13px; margin:2px 0;">Team: First_Timers &bull; Project ID: A3-PS027-TC108</p>
        </div>
        <div>
            {score_badge}
        </div>
    </div>

    {env_banner}

    <div class="summary-grid">
        <div class="card">
            <div class="card-title">Discovered Resources</div>
            <div class="card-value">{len(resources)}</div>
        </div>
        <div class="card">
            <div class="card-title">Unique Hosts</div>
            <div class="card-value">{len(hosts)}</div>
        </div>
        <div class="card">
            <div class="card-title">Dependencies with AAAA</div>
            <div class="card-value">{assessment.get('dependencies', {}).get('with_aaaa', 0)} / {assessment.get('dependencies', {}).get('total_dependencies', 0)}</div>
        </div>
        <div class="card">
            <div class="card-title">IPv6 Dependency Adoption</div>
            <div class="card-value">{assessment.get('dependencies', {}).get('aaaa_adoption_rate_percent', 0)}%</div>
        </div>
    </div>

    <h2>Key Findings & Remediation Steps</h2>
    <table>
        <thead>
            <tr>
                <th>Target Host</th>
                <th>Stage</th>
                <th>Observed Issue</th>
                <th>Evidence / Technical Detail</th>
                <th>Recommended Action</th>
            </tr>
        </thead>
        <tbody>
            {findings_rows}
        </tbody>
    </table>

    <h2>Host Resolution & Dual-Stack Records</h2>
    <table>
        <thead>
            <tr>
                <th>Hostname</th>
                <th>IPv6 Readiness</th>
                <th>IPv4 Address (A)</th>
                <th>IPv6 Address (AAAA)</th>
                <th>DNS Latency (v4/v6)</th>
            </tr>
        </thead>
        <tbody>
            {hosts_rows}
        </tbody>
    </table>

    <div class="footer">
        Generated by <strong>IPv6 Website and Dependency Readiness Auditor</strong> &bull; AIORI Hackathon 3 &bull; References: RFC 8200, RFC 8305
    </div>
</div>
</body>
</html>
"""
    return html
