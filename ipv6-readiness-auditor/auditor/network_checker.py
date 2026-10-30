"""
Network Connectivity Checker.
Detects local environment capabilities (IPv4 & IPv6 outbound reachability),
and performs genuine stage-wise TCP connection testing.
"""

import time
import socket
import errno
from typing import Dict, Any, List, Optional, Tuple

# Well-known public test targets for environmental baseline checks
PUBLIC_V4_TARGETS = [
    ("8.8.8.8", 53),        # Google DNS
    ("1.1.1.1", 53),        # Cloudflare DNS
    ("9.9.9.9", 53),        # Quad9 DNS
]

PUBLIC_V6_TARGETS = [
    ("2001:4860:4860::8888", 53),  # Google Public DNS IPv6
    ("2606:4700:4700::1111", 53),  # Cloudflare DNS IPv6
    ("2620:fe::fe", 53),           # Quad9 DNS IPv6
]


def detect_environment_capabilities(timeout: float = 2.0) -> Dict[str, Any]:
    """
    Determines whether the host running the auditor has working outbound
    IPv4 and IPv6 internet connectivity.
    """
    v4_capable = False
    v4_reason = "No successful outbound IPv4 connection established."
    v6_capable = False
    v6_reason = "No successful outbound IPv6 connection established."

    # Test IPv4
    for host, port in PUBLIC_V4_TARGETS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                v4_capable = True
                v4_reason = f"Outbound IPv4 connectivity verified via {host}:{port}"
                break
        except Exception as e:
            v4_reason = f"IPv4 connection failed ({type(e).__name__}): {e}"

    # Test IPv6
    if hasattr(socket, "AF_INET6"):
        for host, port in PUBLIC_V6_TARGETS:
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((host, port))
                    v6_capable = True
                    v6_reason = f"Outbound IPv6 connectivity verified via {host}:{port}"
                    break
            except OSError as e:
                # Common Windows/Linux error when no IPv6 default route exists:
                # 10051 (WSAENETUNREACH), 10065 (WSAEHOSTUNREACH), 101 (ENETUNREACH)
                err_code = getattr(e, 'errno', None) or getattr(e, 'winerror', None)
                if err_code in (10051, 10065, 101, 113, errno.ENETUNREACH, getattr(errno, 'EHOSTUNREACH', 113)):
                    v6_reason = "Auditor machine has no default IPv6 internet route (Network unreachable)."
                else:
                    v6_reason = f"IPv6 connection failed ({type(e).__name__}): {e}"
            except Exception as e:
                v6_reason = f"IPv6 probe error ({type(e).__name__}): {e}"
    else:
        v6_reason = "Host operating system or Python environment does not support socket.AF_INET6."

    return {
        "ipv4_capable": v4_capable,
        "ipv4_status_message": v4_reason,
        "ipv6_capable": v6_capable,
        "ipv6_status_message": v6_reason,
    }


def check_tcp_connection(
    ip_address: str,
    port: int,
    is_ipv6: bool = False,
    timeout: float = 4.0,
    env_v6_capable: bool = True
) -> Dict[str, Any]:
    """
    Attempts genuine TCP three-way handshake to the specified target IP and port.

    Returns:
      - success: bool
      - ip: str
      - port: int
      - latency_ms: float
      - error_category: Optional[str]
      - error_detail: Optional[str]
      - is_env_limitation: bool
    """
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    result = {
        "success": False,
        "ip": ip_address,
        "port": port,
        "is_ipv6": is_ipv6,
        "latency_ms": 0.0,
        "error_category": None,
        "error_detail": None,
        "is_env_limitation": False,
    }

    if is_ipv6 and not env_v6_capable:
        result["error_category"] = "Environment Limitation"
        result["error_detail"] = "Auditor host network lacks outbound IPv6 connectivity. Live TCP test skipped."
        result["is_env_limitation"] = True
        return result

    t0 = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_address, port))
            latency = (time.perf_counter() - t0) * 1000
            result["success"] = True
            result["latency_ms"] = round(latency, 2)
            return result
    except socket.timeout:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        result["error_category"] = "Timeout"
        result["error_detail"] = f"TCP connection timed out after {timeout}s"
    except ConnectionRefusedError as e:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        result["error_category"] = "Connection Refused"
        result["error_detail"] = f"Port {port} actively refused connection (RST received): {e}"
    except OSError as e:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        err_code = getattr(e, 'errno', None) or getattr(e, 'winerror', None)
        if is_ipv6 and err_code in (10051, 10065, 101, 113, errno.ENETUNREACH, getattr(errno, 'EHOSTUNREACH', 113)):
            result["error_category"] = "Environment Limitation"
            result["error_detail"] = f"Auditor machine has no IPv6 route to destination (Network unreachable): {e}"
            result["is_env_limitation"] = True
        else:
            result["error_category"] = "TCP Connection Error"
            result["error_detail"] = f"Socket error ({type(e).__name__}): {e}"
    except Exception as e:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        result["error_category"] = "Network Error"
        result["error_detail"] = f"Unexpected error ({type(e).__name__}): {e}"

    return result


check_tcp_connection.__test__ = False


