"""
TLS Handshake and Certificate Validation Module.
Performs genuine TLS handshakes with SNI preservation and strict certificate validation.
Distinguishes between certificate validation errors and generic handshake failures.
"""

import time
import ssl
import socket
from typing import Dict, Any, Optional


def test_tls_connection(
    ip_address: str,
    hostname: str,
    port: int = 443,
    is_ipv6: bool = False,
    timeout: float = 5.0,
    env_v6_capable: bool = True
) -> Dict[str, Any]:
    """
    Establishes a TCP connection to the specific target IP and performs a TLS handshake
    using hostname for SNI and strict CA validation.

    Returns:
      - success: bool
      - latency_ms: float
      - tls_version: Optional[str]
      - cipher: Optional[str]
      - cert_subject: Optional[str]
      - cert_issuer: Optional[str]
      - error_category: Optional[str]
      - error_detail: Optional[str]
      - is_env_limitation: bool
    """
    result = {
        "success": False,
        "latency_ms": 0.0,
        "tls_version": None,
        "cipher": None,
        "cert_subject": None,
        "cert_issuer": None,
        "error_category": None,
        "error_detail": None,
        "is_env_limitation": False,
    }

    if is_ipv6 and not env_v6_capable:
        result["error_category"] = "Environment Limitation"
        result["error_detail"] = "Auditor host network lacks outbound IPv6 connectivity. Live TLS test skipped."
        result["is_env_limitation"] = True
        return result

    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    try:
        import certifi
        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()

    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    t0 = time.perf_counter()
    raw_sock = None
    ssl_sock = None
    try:
        raw_sock = socket.socket(family, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip_address, port))

        # Wrap socket with TLS context
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=hostname)
        handshake_time = (time.perf_counter() - t0) * 1000

        result["success"] = True
        result["latency_ms"] = round(handshake_time, 2)
        result["tls_version"] = ssl_sock.version()
        cipher_info = ssl_sock.cipher()
        if cipher_info:
            result["cipher"] = cipher_info[0]

        cert = ssl_sock.getpeercert()
        if cert:
            # Extract common name or subject info
            subject_parts = []
            for sub in cert.get("subject", ()):
                for k, v in sub:
                    if k in ("commonName", "organizationName"):
                        subject_parts.append(f"{k}={v}")
            result["cert_subject"] = ", ".join(subject_parts) if subject_parts else "Present"

            issuer_parts = []
            for iss in cert.get("issuer", ()):
                for k, v in iss:
                    if k in ("commonName", "organizationName"):
                        issuer_parts.append(f"{k}={v}")
            result["cert_issuer"] = ", ".join(issuer_parts) if issuer_parts else "Present"

        return result

    except ssl.SSLCertVerificationError as e:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        result["error_category"] = "TLS Certificate Validation Error"
        result["error_detail"] = f"Certificate verification failed: {e.verify_message} (Code: {e.verify_code})"
    except ssl.SSLError as e:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        result["error_category"] = "TLS Handshake Error"
        result["error_detail"] = f"TLS handshake protocol error: {str(e)}"
    except socket.timeout:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        result["error_category"] = "Timeout"
        result["error_detail"] = f"TLS connection/handshake timed out after {timeout}s"
    except OSError as e:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        err_code = getattr(e, 'errno', None) or getattr(e, 'winerror', None)
        if is_ipv6 and err_code in (10051, 10065, 101, 113):
            result["error_category"] = "Environment Limitation"
            result["error_detail"] = f"Auditor machine has no IPv6 route to destination: {e}"
            result["is_env_limitation"] = True
        else:
            result["error_category"] = "TCP Connection Error"
            result["error_detail"] = f"Underlying TCP socket failed during TLS setup: {e}"
    except Exception as e:
        latency = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency, 2)
        result["error_category"] = "TLS Error"
        result["error_detail"] = f"Unexpected TLS error ({type(e).__name__}): {e}"
    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        elif raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

    return result
