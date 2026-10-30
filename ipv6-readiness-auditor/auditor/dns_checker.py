"""
DNS Analysis module for IPv4 (A) and IPv6 (AAAA) records.
Uses dnspython where available, falling back to socket getaddrinfo,
to accurately measure resolution latency, record availability, and failure causes.
"""

import time
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def check_dns(hostname: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Perform stage-wise DNS resolution for A and AAAA records of a hostname.

    Returns structured results containing:
      - hostname
      - timestamp_utc
      - ipv4_status: "IPv4 DNS available" | "IPv4 DNS unavailable" | "DNS resolution error" | "DNS test inconclusive"
      - ipv6_status: "IPv6 DNS available" | "IPv6 DNS unavailable" | "DNS resolution error" | "DNS test inconclusive"
      - ipv4_addresses: List[str]
      - ipv6_addresses: List[str]
      - ipv4_lookup_time_ms: float
      - ipv6_lookup_time_ms: float
      - error_ipv4: Optional[str]
      - error_ipv6: Optional[str]
      - overall_dns_status: str
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    result: Dict[str, Any] = {
        "hostname": hostname,
        "timestamp_utc": timestamp,
        "ipv4_status": "DNS test inconclusive",
        "ipv6_status": "DNS test inconclusive",
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "ipv4_lookup_time_ms": 0.0,
        "ipv6_lookup_time_ms": 0.0,
        "error_ipv4": None,
        "error_ipv6": None,
        "overall_dns_status": "Inconclusive",
    }

    if not hostname:
        result["overall_dns_status"] = "DNS resolution error"
        result["error_ipv4"] = "Missing hostname"
        result["error_ipv6"] = "Missing hostname"
        return result

    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # 1. Resolve A (IPv4)
        t0 = time.perf_counter()
        try:
            answers_a = resolver.resolve(hostname, 'A')
            result["ipv4_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv4_addresses"] = [r.address for r in answers_a]
            result["ipv4_status"] = "IPv4 DNS available"
        except dns.resolver.NoAnswer:
            result["ipv4_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv4_status"] = "IPv4 DNS unavailable"
            result["error_ipv4"] = "No A record found (NODATA)"
        except dns.resolver.NXDOMAIN:
            result["ipv4_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv4_status"] = "DNS resolution error"
            result["error_ipv4"] = f"Domain does not exist (NXDOMAIN): {hostname}"
        except dns.exception.Timeout:
            result["ipv4_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv4_status"] = "DNS test inconclusive"
            result["error_ipv4"] = f"DNS query timed out after {timeout}s"
        except Exception as e:
            result["ipv4_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv4_status"] = "DNS resolution error"
            result["error_ipv4"] = str(e)

        # 2. Resolve AAAA (IPv6)
        t0 = time.perf_counter()
        try:
            answers_aaaa = resolver.resolve(hostname, 'AAAA')
            result["ipv6_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv6_addresses"] = [r.address for r in answers_aaaa]
            result["ipv6_status"] = "IPv6 DNS available"
        except dns.resolver.NoAnswer:
            result["ipv6_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv6_status"] = "IPv6 DNS unavailable"
            result["error_ipv6"] = "No AAAA record found (NODATA)"
        except dns.resolver.NXDOMAIN:
            result["ipv6_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv6_status"] = "DNS resolution error"
            result["error_ipv6"] = f"Domain does not exist (NXDOMAIN): {hostname}"
        except dns.exception.Timeout:
            result["ipv6_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv6_status"] = "DNS test inconclusive"
            result["error_ipv6"] = f"DNS query timed out after {timeout}s"
        except Exception as e:
            result["ipv6_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv6_status"] = "DNS resolution error"
            result["error_ipv6"] = str(e)

    else:
        # Fallback to standard library getaddrinfo
        t0 = time.perf_counter()
        try:
            v4_info = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            result["ipv4_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv4_addresses"] = list(dict.fromkeys([item[4][0] for item in v4_info]))
            result["ipv4_status"] = "IPv4 DNS available" if result["ipv4_addresses"] else "IPv4 DNS unavailable"
        except socket.gaierror as e:
            result["ipv4_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv4_status"] = "IPv4 DNS unavailable"
            result["error_ipv4"] = str(e)
        except Exception as e:
            result["ipv4_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv4_status"] = "DNS resolution error"
            result["error_ipv4"] = str(e)

        t0 = time.perf_counter()
        try:
            v6_info = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
            result["ipv6_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv6_addresses"] = list(dict.fromkeys([item[4][0] for item in v6_info]))
            result["ipv6_status"] = "IPv6 DNS available" if result["ipv6_addresses"] else "IPv6 DNS unavailable"
        except socket.gaierror as e:
            result["ipv6_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv6_status"] = "IPv6 DNS unavailable"
            result["error_ipv6"] = str(e)
        except Exception as e:
            result["ipv6_lookup_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["ipv6_status"] = "DNS resolution error"
            result["error_ipv6"] = str(e)

    # Classify overall DNS status
    has_v4 = bool(result["ipv4_addresses"])
    has_v6 = bool(result["ipv6_addresses"])

    if has_v4 and has_v6:
        result["overall_dns_status"] = "Dual-Stack DNS (A + AAAA)"
    elif has_v6 and not has_v4:
        result["overall_dns_status"] = "IPv6-Only DNS (AAAA)"
    elif has_v4 and not has_v6:
        result["overall_dns_status"] = "IPv4-Only DNS (A)"
    elif result["ipv4_status"] == "DNS resolution error" or result["ipv6_status"] == "DNS resolution error":
        result["overall_dns_status"] = "DNS Resolution Error"
    elif result["ipv4_status"] == "DNS test inconclusive" or result["ipv6_status"] == "DNS test inconclusive":
        result["overall_dns_status"] = "DNS Query Timeout / Inconclusive"
    else:
        result["overall_dns_status"] = "No IP Records"

    return result
