"""
IPv6 Website and Dependency Readiness Auditor - Streamlit Application
Team: First_Timers (Nachan HaazalAli Danish, Eshaan Brahmi)
AIORI Hackathon 3 | Project ID: A3-PS027-TC108
"""

import time
import json
from datetime import datetime, timezone
import streamlit as st
import pandas as pd

from auditor.audit_orchestrator import run_full_audit
from auditor.report_generator import generate_json_report, generate_csv_report, generate_html_report
from auditor.network_checker import detect_environment_capabilities
from auditor.url_validation import validate_and_normalize_url

# Page configuration
st.set_page_config(
    page_title="IPv6 Readiness Auditor | First_Timers",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom styling for professional dark cybersecurity / network engineering aesthetic
st.markdown("""
<style>
    /* Metric styling */
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem;
        font-weight: 700;
        color: #38bdf8;
    }
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 20px;
    }
    .badge-pill {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .badge-ready { background-color: #065f46; color: #34d399; }
    .badge-warn { background-color: #78350f; color: #fbbf24; }
    .badge-danger { background-color: #7f1d1d; color: #f87171; }
    .badge-info { background-color: #1e3a8a; color: #60a5fa; }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if "audit_history" not in st.session_state:
    st.session_state.audit_history = []
if "current_audit" not in st.session_state:
    st.session_state.current_audit = None
if "env_caps" not in st.session_state:
    st.session_state.env_caps = detect_environment_capabilities()

env = st.session_state.env_caps

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/network-switch.png", width=64)
    st.title("IPv6 Readiness Auditor")
    st.caption("**Team:** First_Timers  \n**Project ID:** A3-PS027-TC108  \n**Hackathon:** AIORI Hackathon 3")
    st.markdown("---")

    st.subheader("Auditor Host Environment")
    if env.get("ipv4_capable"):
        st.success("IPv4 Outbound: Active")
    else:
        st.error("IPv4 Outbound: Unavailable")

    if env.get("ipv6_capable"):
        st.success("IPv6 Outbound: Active")
    else:
        st.warning("IPv6 Outbound: Route Not Present (DNS queries active; live TCP tests restricted)")

    st.markdown("---")
    st.subheader("Quick Presets")
    preset_choice = st.selectbox(
        "Choose a test target:",
        [
            "Custom URL...",
            "https://example.com (Dual-Stack Root)",
            "https://www.wikipedia.org (Global Dual-Stack)",
            "https://www.google.com (Extensive CDN & APIs)",
            "https://ipv4.google.com (Strict IPv4-Only Endpoint)",
        ]
    )

    st.markdown("---")
    st.info("💡 **Methodology:** Conforms to RFC 8200 (IPv6 Specification) & RFC 8305 (Happy Eyeballs v2 dual-stack measurements).")

# Main Header
st.markdown("""
<div class="main-header">
    <h2 style="margin:0; color:#f8fafc;">🌐 IPv6 Website and Dependency Readiness Auditor</h2>
    <p style="margin:5px 0 0 0; color:#94a3b8; font-size:0.95rem;">
        Automated multi-stage readiness auditing across browser dependency discovery, DNS (A/AAAA), TCP, TLS, and HTTP dual-stack connectivity.
    </p>
</div>
""", unsafe_allow_html=True)

# Input Section
col_input, col_btn = st.columns([5, 1])

default_url = "https://example.com"
if preset_choice != "Custom URL...":
    default_url = preset_choice.split(" ")[0]

with col_input:
    target_input = st.text_input(
        "Target Website URL",
        value=default_url,
        placeholder="https://example.com",
        help="Enter a public website URL. Private addresses and SSRF attempts are blocked."
    )

with col_btn:
    st.write("")
    st.write("")
    run_btn = st.button("🚀 Audit Site", use_container_width=True, type="primary")

# Run Audit Workflow
if run_btn:
    if not target_input.strip():
        st.error("Please enter a valid target URL.")
    else:
        # Validate immediately
        is_valid, norm_url, err_msg, host, port, scheme = validate_and_normalize_url(target_input)
        if not is_valid:
            st.error(f"❌ Input Validation Error: {err_msg}")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()

            def update_ui(pct: int, msg: str):
                progress_bar.progress(pct)
                status_text.text(f"[{pct}%] {msg}")

            with st.spinner("Executing full dual-stack audit..."):
                audit_res = run_full_audit(norm_url, progress_callback=update_ui)

            progress_bar.empty()
            status_text.empty()

            if audit_res.get("success"):
                st.session_state.current_audit = audit_res
                # Save into history
                st.session_state.audit_history.append({
                    "timestamp": audit_res["audit_timestamp_utc"],
                    "url": audit_res["target_url"],
                    "host": audit_res["target_host"],
                    "score": audit_res["assessment"]["overall_score"],
                    "category": audit_res["assessment"]["overall_category"],
                    "data": audit_res
                })
                st.success(f"Audit completed for **{audit_res['target_host']}**!")
            else:
                st.error(f"Audit failed: {audit_res.get('error')}")

# Display Audit Results
audit = st.session_state.current_audit

if audit:
    assessment = audit["assessment"]
    hosts = audit["hosts"]
    resources = audit["resources"]
    findings = audit["findings"]
    target_host = audit["target_host"]

    # Environment Banner if applicable
    if assessment.get("is_environment_limited"):
        st.warning(f"⚠️ **Auditor Host Limitation:** {assessment.get('environment_notice')}")

    # Tabs for organized view
    tab_overview, tab_graph, tab_resources, tab_diagnostics, tab_findings, tab_exports, tab_history = st.tabs([
        "📊 Overview",
        "🕸️ Dependency Graph",
        "📦 Resource Explorer",
        "🔬 Network Diagnostics",
        "⚠️ Findings & Fixes",
        "📥 Export Reports",
        "🕒 Audit Comparison"
    ])

    # TAB 1: OVERVIEW
    with tab_overview:
        score = assessment["overall_score"]
        category = assessment["overall_category"]

        st.markdown(f"### Overall Readiness: **{category}**")

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Readiness Score", f"{score} / 100")
        c2.metric("Discovered Resources", len(resources))
        c3.metric("Unique Hosts", len(hosts))
        c4.metric("Dependencies with AAAA", f"{assessment['dependencies']['with_aaaa']} / {assessment['dependencies']['total_dependencies']}")
        c5.metric("IPv6 Adoption Rate", f"{assessment['dependencies']['aaaa_adoption_rate_percent']}%")

        st.markdown("---")

        col_main, col_dep = st.columns(2)
        with col_main:
            st.subheader("Main Domain Readiness")
            main_dom = assessment["main_domain"]
            st.write(f"**Target Host:** `{main_dom['hostname']}`")
            st.write(f"**IPv4 Addresses (A):** {', '.join(main_dom['ipv4_addresses']) if main_dom['ipv4_addresses'] else 'None'}")
            st.write(f"**IPv6 Addresses (AAAA):** {', '.join(main_dom['ipv6_addresses']) if main_dom['ipv6_addresses'] else 'None (NODATA)'}")
            if main_dom['has_aaaa']:
                st.success("✅ Main host publishes valid IPv6 AAAA DNS records.")
            else:
                st.error("❌ Main host does not publish any IPv6 AAAA DNS records.")

        with col_dep:
            st.subheader("Observed Dependency Ecosystem")
            deps = assessment["dependencies"]
            st.write(f"**Total Third-Party Hosts:** {deps['total_dependencies']}")
            st.write(f"**Dual-Stack Ready Dependencies:** {deps['with_aaaa']}")
            st.write(f"**IPv4-Only Dependencies:** {deps['ipv4_only']}")
            st.write(f"**Unresolvable / DNS Errors:** {deps['dns_failed']}")

            # Mini breakdown bar
            if deps['total_dependencies'] > 0:
                st.progress(deps['with_aaaa'] / deps['total_dependencies'])

    # TAB 2: DEPENDENCY GRAPH
    with tab_graph:
        st.subheader("Website Dependency Graph & IPv6 Connectivity Map")
        st.caption("Central node is the target website. Surrounding nodes represent discovered first-party and third-party dependencies. Colors denote IPv6 DNS and live connection states.")
        if "graph_figure" in audit and audit["graph_figure"]:
            st.plotly_chart(audit["graph_figure"], use_container_width=True)
        else:
            st.info("No dependency graph available.")

    # TAB 3: RESOURCE EXPLORER
    with tab_resources:
        st.subheader("Browser-Discovered Page Resources")
        st.caption(f"Discovery method: {audit['discovery_summary']['method']} | Page Title: '{audit['discovery_summary']['page_title']}'")

        if resources:
            df_res = pd.DataFrame(resources)
            # Filter options
            f_col1, f_col2, f_col3 = st.columns(3)
            with f_col1:
                selected_type = st.multiselect("Filter Resource Type:", options=sorted(df_res["resource_type"].unique().tolist()))
            with f_col2:
                selected_party = st.selectbox("Party Filter:", ["All", "First-Party Only", "Third-Party Only"])
            with f_col3:
                search_query = st.text_input("Search URL or Host:", "")

            filtered_df = df_res.copy()
            if selected_type:
                filtered_df = filtered_df[filtered_df["resource_type"].isin(selected_type)]
            if selected_party == "First-Party Only":
                filtered_df = filtered_df[~filtered_df["is_third_party"]]
            elif selected_party == "Third-Party Only":
                filtered_df = filtered_df[filtered_df["is_third_party"]]
            if search_query:
                filtered_df = filtered_df[filtered_df["url"].str.contains(search_query, case=False, na=False) | filtered_df["hostname"].str.contains(search_query, case=False, na=False)]

            display_cols = ["url", "hostname", "resource_type", "is_third_party", "method", "status_code", "duration_ms"]
            st.dataframe(filtered_df[display_cols], use_container_width=True, hide_index=True)
            st.caption(f"Showing {len(filtered_df)} of {len(df_res)} resources.")
        else:
            st.info("No resources were captured.")

    # TAB 4: NETWORK DIAGNOSTICS
    with tab_diagnostics:
        st.subheader("Host-by-Host Stage-Wise Diagnostics")
        st.caption("Explicit stage separation: DNS (A/AAAA) ➡️ TCP Handshake ➡️ TLS Negotiation ➡️ HTTP Response.")

        for h, data in hosts.items():
            dns_info = data.get("dns", {})
            v4_tcp = data.get("v4_tcp", {})
            v6_tcp = data.get("v6_tcp", {})
            v4_tls = data.get("v4_tls", {})
            v6_tls = data.get("v6_tls", {})
            v4_http = data.get("v4_http", {})
            v6_http = data.get("v6_http", {})

            with st.expander(f"🌐 Host: **{h}** {'(Main Target)' if h == target_host else ''}", expanded=(h == target_host)):
                diag_c1, diag_c2 = st.columns(2)

                with diag_c1:
                    st.markdown("#### IPv4 Pipeline")
                    st.write(f"**DNS A Record:** {', '.join(dns_info.get('ipv4_addresses', [])) or 'None'} ({dns_info.get('ipv4_lookup_time_ms', 0)} ms)")
                    if v4_tcp.get("success"):
                        st.write(f"**TCP Connect:** ✅ Success ({v4_tcp.get('latency_ms')} ms)")
                    else:
                        st.write(f"**TCP Connect:** ❌ {v4_tcp.get('error_category', 'Not Run')}")

                    if v4_tls.get("success"):
                        st.write(f"**TLS Handshake:** ✅ Valid ({v4_tls.get('tls_version')}, {v4_tls.get('latency_ms')} ms)")
                    elif v4_tls.get("error_category"):
                        st.write(f"**TLS Handshake:** ❌ {v4_tls.get('error_category')}")

                    if v4_http.get("success"):
                        st.write(f"**HTTP Response:** ✅ HTTP {v4_http.get('status_code')} {v4_http.get('reason')} ({v4_http.get('latency_ms')} ms)")
                    elif v4_http.get("error_category"):
                        st.write(f"**HTTP Response:** ⚠️ {v4_http.get('error_category')}")

                with diag_c2:
                    st.markdown("#### IPv6 Pipeline")
                    st.write(f"**DNS AAAA Record:** {', '.join(dns_info.get('ipv6_addresses', [])) or 'None (NODATA)'} ({dns_info.get('ipv6_lookup_time_ms', 0)} ms)")
                    if not dns_info.get("ipv6_addresses"):
                        st.warning("No IPv6 addresses published in DNS.")
                    else:
                        if v6_tcp.get("success"):
                            st.write(f"**TCP Connect:** ✅ Success ({v6_tcp.get('latency_ms')} ms)")
                        elif v6_tcp.get("is_env_limitation"):
                            st.info(f"**TCP Connect:** ⚠️ Auditor Host Environment Limited ({v6_tcp.get('error_detail')})")
                        else:
                            st.write(f"**TCP Connect:** ❌ {v6_tcp.get('error_category', 'Failed')}")

                        if v6_tls.get("success"):
                            st.write(f"**TLS Handshake:** ✅ Valid ({v6_tls.get('tls_version')}, {v6_tls.get('latency_ms')} ms)")
                        elif v6_tls.get("is_env_limitation"):
                            st.info("**TLS Handshake:** ⚠️ Auditor Host Environment Limited")
                        elif v6_tls.get("error_category"):
                            st.write(f"**TLS Handshake:** ❌ {v6_tls.get('error_category')}")

                        if v6_http.get("success"):
                            st.write(f"**HTTP Response:** ✅ HTTP {v6_http.get('status_code')} {v6_http.get('reason')} ({v6_http.get('latency_ms')} ms)")
                        elif v6_http.get("is_env_limitation"):
                            st.info("**HTTP Response:** ⚠️ Auditor Host Environment Limited")
                        elif v6_http.get("error_category"):
                            st.write(f"**HTTP Response:** ⚠️ {v6_http.get('error_category')}")

    # TAB 5: FINDINGS & FIXES
    with tab_findings:
        st.subheader("Actionable Findings & Diagnostic Recommendations")
        st.caption("Prioritized failure analysis based on observed network tests.")

        if findings:
            for f in findings:
                is_high = f.get("confidence") == "High"
                with st.container():
                    st.markdown(f"#### {f.get('failure_category')} — `{f.get('hostname')}`")
                    st.write(f"**Failure Stage:** `{f.get('stage')}` | **Family:** {f.get('address_family')} | **Confidence:** {f.get('confidence')}")
                    st.write(f"**Observed Issue:** {f.get('observed_failure')}")
                    st.info(f"**Technical Evidence:** {f.get('evidence')}")
                    st.success(f"🔧 **Recommended Action:** {f.get('recommendation')}")
                    st.markdown("---")
        else:
            st.success("🎉 No connectivity errors or IPv6 compatibility blockers detected!")

    # TAB 6: EXPORT REPORTS
    with tab_exports:
        st.subheader("Download Audit Reports")
        st.write("Export verifiable audit reports for documentation, hackathon judging, and archiving.")

        json_str = generate_json_report(audit)
        csv_str = generate_csv_report(audit)
        html_str = generate_html_report(audit)

        col_d1, col_d2, col_d3 = st.columns(3)
        with col_d1:
            st.download_button(
                label="📄 Download JSON Audit Report",
                data=json_str,
                file_name=f"ipv6_audit_{target_host}_{int(time.time())}.json",
                mime="application/json",
                use_container_width=True
            )
        with col_d2:
            st.download_button(
                label="📊 Download CSV Resource List",
                data=csv_str,
                file_name=f"ipv6_resources_{target_host}_{int(time.time())}.csv",
                mime="text/csv",
                use_container_width=True
            )
        with col_d3:
            st.download_button(
                label="🌐 Download Standalone HTML Report",
                data=html_str,
                file_name=f"ipv6_report_{target_host}_{int(time.time())}.html",
                mime="text/html",
                use_container_width=True
            )

        st.markdown("---")
        st.subheader("HTML Report Preview")
        st.components.v1.html(html_str, height=500, scrolling=True)

    # TAB 7: AUDIT COMPARISON
    with tab_history:
        st.subheader("Historical Audit Runs & Ecosystem Comparison")
        if len(st.session_state.audit_history) > 1:
            st.write("Compare two previously executed audits:")
            h_labels = [f"{i+1}. {item['host']} ({item['score']}/100) @ {item['timestamp'][:19]}" for i, item in enumerate(st.session_state.audit_history)]
            comp1 = st.selectbox("Select Baseline Audit:", h_labels, index=0)
            comp2 = st.selectbox("Select Comparison Audit:", h_labels, index=len(h_labels)-1)

            idx1 = h_labels.index(comp1)
            idx2 = h_labels.index(comp2)

            data1 = st.session_state.audit_history[idx1]["data"]
            data2 = st.session_state.audit_history[idx2]["data"]

            c_comp1, c_comp2 = st.columns(2)
            with c_comp1:
                st.markdown(f"**Baseline: {data1['target_host']}**")
                st.metric("Readiness Score", f"{data1['assessment']['overall_score']}/100")
                st.write(f"Category: {data1['assessment']['overall_category']}")
                st.write(f"Total Hosts: {len(data1['hosts'])}")
            with c_comp2:
                st.markdown(f"**Comparison: {data2['target_host']}**")
                st.metric("Readiness Score", f"{data2['assessment']['overall_score']}/100", delta=round(data2['assessment']['overall_score'] - data1['assessment']['overall_score'], 1))
                st.write(f"Category: {data2['assessment']['overall_category']}")
                st.write(f"Total Hosts: {len(data2['hosts'])}")
        else:
            st.info("Execute audits on two or more sites to unlock cross-website readiness comparisons.")

else:
    # Landing instructions
    st.markdown("""
    ### Welcome to the IPv6 Readiness Auditor
    To begin auditing, enter a website URL above (or choose one from the quick presets in the sidebar) and click **Audit Site**.

    #### What happens during an audit?
    1. **SSRF & Security Validation:** Blocks internal addresses, loopbacks, and link-local ranges.
    2. **Host Capability Detection:** Checks local network IPv4 and IPv6 routes.
    3. **Browser Resource Discovery:** Automates headless Chromium to fetch the webpage and detect all dependent scripts, images, styles, and APIs.
    4. **Dual-Stack DNS Inspection:** Resolves `A` (IPv4) and `AAAA` (IPv6) records, measuring query latencies.
    5. **Stage-Wise Network Probing:** Conducts genuine TCP three-way handshakes, TLS SNI negotiation, and HTTP tests.
    6. **Failure Root-Cause Classification:** Pinpoints exact failure points (DNS vs TCP vs TLS vs HTTP vs Browser policies).
    7. **Dependency Graph & Reports:** Renders an interactive Plotly graph and provides exportable JSON, CSV, and HTML reports.
    """)
