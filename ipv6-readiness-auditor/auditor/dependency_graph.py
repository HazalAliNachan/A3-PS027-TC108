"""
Interactive Dependency Graph Generator using NetworkX and Plotly.
Visualizes the relationship between the target root host and discovered dependencies,
encoding IPv6 readiness states into visual colors, sizes, and hover metadata.
"""

import math
from typing import Dict, Any, List
import plotly.graph_objects as go
import networkx as nx


def generate_dependency_graph(
    target_host: str,
    hosts_data: Dict[str, Dict[str, Any]],
    resources: List[Dict[str, Any]]
) -> go.Figure:
    """
    Builds an interactive Plotly graph figure representing the audited website ecosystem.
    """
    G = nx.Graph()

    # Add central target node
    G.add_node(target_host, is_target=True)

    # Compute resource count and types per host
    host_resources_count: Dict[str, int] = {}
    host_types_map: Dict[str, set] = {}

    for r in resources:
        h = r.get("hostname", "")
        if not h:
            continue
        host_resources_count[h] = host_resources_count.get(h, 0) + 1
        rtype = r.get("resource_type", "other")
        if h not in host_types_map:
            host_types_map[h] = set()
        host_types_map[h].add(rtype)

    # Add dependency nodes and edges
    for host in hosts_data.keys():
        if host != target_host:
            G.add_node(host, is_target=False)
            G.add_edge(target_host, host)

    # Compute node positions using spring layout or radial layout
    pos = nx.spring_layout(G, seed=42, k=0.5 if len(G.nodes) > 1 else 1.0)
    # Ensure central host is at center (0, 0)
    pos[target_host] = (0.0, 0.0)

    # Separate traces for edges and nodes
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1.2, color="#4a5568"),
        hoverinfo="none",
        mode="lines"
    )

    node_x = []
    node_y = []
    node_colors = []
    node_sizes = []
    node_text = []
    node_labels = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        h_data = hosts_data.get(node, {})
        dns_info = h_data.get("dns", {})
        v6_tcp = h_data.get("v6_tcp", {})
        v4_tcp = h_data.get("v4_tcp", {})
        has_aaaa = bool(dns_info.get("ipv6_addresses"))
        has_a = bool(dns_info.get("ipv4_addresses"))

        res_count = host_resources_count.get(node, 1)
        res_types = ", ".join(sorted(list(host_types_map.get(node, {"document"}))))

        # Determine color status
        if node == target_host:
            # Main site
            if has_aaaa and (v6_tcp.get("success", False) or dns_info.get("ipv6_status") == "IPv6 DNS available"):
                color = "#00cc96"  # Emerald Green
                status_label = "IPv6 Dual-Stack Ready"
            elif not has_aaaa:
                color = "#ef553b"  # Red / Warning
                status_label = "IPv4-Only (No AAAA Record)"
            else:
                color = "#ab63fa"  # Dual-Stack DNS
                status_label = "Dual-Stack DNS Verified"
            size = 34
        else:
            if has_aaaa and v6_tcp.get("success", False):
                color = "#00cc96"  # Green
                status_label = "IPv6 Connected"
            elif has_aaaa and v6_tcp.get("is_env_limitation", False):
                color = "#19d3f3"  # Cyan / Blue - DNS Ready, host env limitation
                status_label = "IPv6 AAAA Available (Env Limited)"
            elif has_aaaa and not v6_tcp.get("success", True):
                color = "#ef553b"  # Red
                status_label = "IPv6 TCP Connection Failed"
            elif has_a and not has_aaaa:
                color = "#ffa15a"  # Orange
                status_label = "IPv4-Only Dependency"
            else:
                color = "#b6b6b6"  # Grey
                status_label = "Inconclusive / DNS Failed"
            size = min(14 + int(math.log2(res_count + 1) * 6), 28)

        node_colors.append(color)
        node_sizes.append(size)
        node_labels.append(node if len(node) <= 22 else node[:20] + "..")

        hover_info = (
            f"<b>{node}</b><br>"
            f"Role: {'Target Website' if node == target_host else 'Observed Dependency'}<br>"
            f"Status: {status_label}<br>"
            f"Resources Loaded: {res_count}<br>"
            f"Types: {res_types}<br>"
            f"IPv4 (A): {len(dns_info.get('ipv4_addresses', []))} records<br>"
            f"IPv6 (AAAA): {len(dns_info.get('ipv6_addresses', []))} records"
        )
        node_text.append(hover_info)

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        hoverinfo="text",
        text=node_labels,
        textposition="top center",
        hovertext=node_text,
        marker=dict(
            showscale=False,
            color=node_colors,
            size=node_sizes,
            line=dict(width=2, color="#ffffff")
        )
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(
                text="<b>Website Dependency Ecosystem & IPv6 Readiness Graph</b>",
                font=dict(size=16, color="#f8fafc")
            ),
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=10, r=10, t=40),
            paper_bgcolor="#0e1726",
            plot_bgcolor="#0e1726",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            annotations=[
                dict(
                    text="● <span style='color:#00cc96'>IPv6 Verified</span>  |  "
                         "● <span style='color:#19d3f3'>IPv6 DNS Ready (Auditor Env Limited)</span>  |  "
                         "● <span style='color:#ffa15a'>IPv4-Only Dependency</span>  |  "
                         "● <span style='color:#ef553b'>Connection / DNS Failure</span>",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.5, y=-0.08,
                    xanchor="center",
                    font=dict(size=12, color="#cbd5e1")
                )
            ]
        )
    )
    return fig
