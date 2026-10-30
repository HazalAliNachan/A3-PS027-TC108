"""
HTTP / HTTPS stage testing module.
Issues safe HEAD / GET requests to specific target IPs over IPv4 or IPv6
with Host header preservation and SNI negotiation.
"""

import time
import socket
import ssl
import http.client
from typing import Dict, Any, Optional

try:
    import certifi
    CA_FILE = certifi.where()
except ImportError:
    CA_FILE = None


class TargetIPHTTPSConnection(http.client.HTTPSConnection):
    """
    Custom HTTPSConnection that binds to an explicit target IP address
    while maintaining the proper server_hostname for TLS SNI and certificate verification.
    """
    def __init__(self, target_ip: str, target_port: int, server_hostname: str, timeout: float = 5.0, context: Optional[ssl.SSLContext] = None):
        super().__init__(target_ip, target_port, timeout=timeout, context=context)
        self.server_hostname = server_hostname

    def connect(self):
        # Socket creation with explicit family support (e.g. IPv6 literal address)
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.server_hostname)


def test_http_endpoint(
    ip_address: str,
    hostname: str,
    port: int = 443,
    scheme: str = "https",
    path: str = "/",
    is_ipv6: bool = False,
    timeout: float = 5.0,
    env_v6_capable: bool = True
) -> Dict[str, Any]:
    """
    Attempts a safe HTTP HEAD (falling back to GET with 32KB limit) request
    against the specified IP address, recording status, headers, latency, and redirect targets.
    """
    result = {
        "success": False,
        "status_code": None,
        "reason": None,
        "latency_ms": 0.0,
        "redirect_url": None,
        "content_type": None,
        "error_category": None,
        "error_detail": None,
        "is_env_limitation": False,
    }

    if is_ipv6 and not env_v6_capable:
        result["error_category"] = "Environment Limitation"
        result["error_detail"] = "Auditor host network lacks outbound IPv6 connectivity. Live HTTP test skipped."
        result["is_env_limitation"] = True
        return result

    headers = {
        "Host": hostname,
        "User-Agent": "IPv6ReadinessAuditor/1.0 (Hackathon; Team First_Timers)",
        "Accept": "*/*",
        "Connection": "close",
    }

    t0 = time.perf_counter()
    conn = None
    try:
        if scheme == "https" or port == 443:
            ctx = ssl.create_default_context(cafile=CA_FILE) if CA_FILE else ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            conn = TargetIPHTTPSConnection(ip_address, port, server_hostname=hostname, timeout=timeout, context=ctx)
        else:
            # Plain HTTP
            formatted_ip = f"[{ip_address}]" if is_ipv6 else ip_address
            conn = http.client.HTTPConnection(formatted_ip, port, timeout=timeout)

        # Send HEAD first
        conn.request("HEAD", path, headers=headers)
        response = conn.getresponse()
        elapsed = (time.perf_counter() - t0) * 1000

        # Some web servers disallow HEAD (405 Method Not Allowed)
        if response.status == 405:
            conn.close()
            t0 = time.perf_counter()
            if scheme == "https" or port == 443:
                ctx = ssl.create_default_context(cafile=CA_FILE) if CA_FILE else ssl.create_default_context()
                ctx.check_hostname = True
                conn = TargetIPHTTPSConnection(ip_address, port, server_hostname=hostname, timeout=timeout, context=ctx)
            else:
                formatted_ip = f"[{ip_address}]" if is_ipv6 else ip_address
                conn = http.client.HTTPConnection(formatted_ip, port, timeout=timeout)
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            # Read at most 32KB safely
            _ = response.read(32768)
            elapsed = (time.perf_counter() - t0) * 1000

        result["success"] = True
        result["status_code"] = response.status
        result["reason"] = response.reason
        result["latency_ms"] = round(elapsed, 2)
        result["content_type"] = response.getheader("Content-Type")
        result["redirect_url"] = response.getheader("Location")

        # Classify HTTP response
        if response.status >= 500:
            result["error_category"] = "HTTP Server Error"
            result["error_detail"] = f"HTTP {response.status} {response.reason}"
        elif response.status >= 400:
            result["error_category"] = "HTTP Client Error"
            result["error_detail"] = f"HTTP {response.status} {response.reason}"

        return result

    except ssl.SSLCertVerificationError as e:
        elapsed = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(elapsed, 2)
        result["error_category"] = "TLS Certificate Validation Error"
        result["error_detail"] = str(e)
    except ssl.SSLError as e:
        elapsed = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(elapsed, 2)
        result["error_category"] = "TLS Handshake Error"
        result["error_detail"] = str(e)
    except socket.timeout:
        elapsed = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(elapsed, 2)
        result["error_category"] = "Timeout"
        result["error_detail"] = f"HTTP request timed out after {timeout}s"
    except OSError as e:
        elapsed = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(elapsed, 2)
        err_code = getattr(e, 'errno', None) or getattr(e, 'winerror', None)
        if is_ipv6 and err_code in (10051, 10065, 101, 113):
            result["error_category"] = "Environment Limitation"
            result["error_detail"] = f"Auditor machine has no IPv6 route to destination: {e}"
            result["is_env_limitation"] = True
        else:
            result["error_category"] = "Network Error"
            result["error_detail"] = f"Connection error: {e}"
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(elapsed, 2)
        result["error_category"] = "HTTP Error"
        result["error_detail"] = f"{type(e).__name__}: {str(e)}"
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return result
