"""
URL validation and SSRF defense module.
Validates target website URLs, normalizes formatting, and enforces security
controls against Server-Side Request Forgery (SSRF) and private network access.
"""

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional, List


def is_prohibited_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Check if an IP string belongs to prohibited ranges:
    loopback, private, link-local, multicast, unspecified, or cloud metadata.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, None

    if ip.is_loopback:
        return True, f"Loopback address ({ip}) is not permitted."
    if ip.is_private:
        return True, f"Private network address ({ip}) is not permitted."
    if ip.is_link_local:
        return True, f"Link-local address ({ip}) is not permitted."
    if ip.is_multicast:
        return True, f"Multicast address ({ip}) is not permitted."
    if ip.is_unspecified:
        return True, f"Unspecified address ({ip}) is not permitted."
    if ip.is_reserved:
        return True, f"Reserved address ({ip}) is not permitted."

    # Specific cloud metadata checks
    if ip_str == "169.254.169.254":
        return True, "Cloud metadata IP address is strictly prohibited."

    return False, None


def validate_and_normalize_url(url: str, check_dns_ssrf: bool = True) -> Tuple[bool, str, Optional[str], Optional[str], int, Optional[str]]:
    """
    Validates and normalizes an input URL.

    Returns:
        (is_valid, normalized_url, error_message, hostname, port, scheme)
    """
    if not url or not isinstance(url, str):
        return False, "", "URL cannot be empty.", None, 0, None

    trimmed = url.strip()

    # Prepend https:// if scheme is missing
    if not trimmed.startswith(("http://", "https://")):
        if "://" in trimmed:
            scheme = trimmed.split("://")[0]
            return False, trimmed, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are allowed.", None, 0, None
        trimmed = "https://" + trimmed

    try:
        parsed = urlparse(trimmed)
    except Exception as e:
        return False, trimmed, f"Malformed URL syntax: {str(e)}", None, 0, None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, trimmed, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are allowed.", None, 0, None

    hostname = parsed.hostname
    if not hostname:
        return False, trimmed, "URL is missing a valid hostname.", None, 0, None

    hostname = hostname.lower()

    # Reject localhost directly
    if hostname in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return False, trimmed, "Access to localhost is prohibited for security.", None, 0, None

    # Check if hostname itself is an IP literal
    is_proh, reason = is_prohibited_ip(hostname)
    if is_proh:
        return False, trimmed, f"Target IP is prohibited: {reason}", None, 0, None

    # Determine default port
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80

    # Ensure path is at least '/'
    path = parsed.path if parsed.path else "/"

    normalized = urlunparse((
        scheme,
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        ""  # strip fragments
    ))

    # SSRF DNS verification: ensure hostname does not resolve to private/loopback IPs
    if check_dns_ssrf:
        try:
            # Check IPv4 and IPv6 resolution for the hostname
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = {item[4][0] for item in addr_info}
            for resolved_ip in resolved_ips:
                is_proh, reason = is_prohibited_ip(resolved_ip)
                if is_proh:
                    return False, normalized, f"Security violation: {hostname} resolves to prohibited address {resolved_ip} ({reason})", None, 0, None
        except socket.gaierror:
            # Let the DNS analyzer handle non-existent domains gracefully during audit
            pass
        except Exception:
            pass

    return True, normalized, None, hostname, port, scheme
