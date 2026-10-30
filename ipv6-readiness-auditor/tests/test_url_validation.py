"""
Unit tests for URL validation and SSRF defenses.
"""

import pytest
from auditor.url_validation import validate_and_normalize_url, is_prohibited_ip


def test_valid_https_url():
    valid, norm, err, host, port, scheme = validate_and_normalize_url("https://example.com/test", check_dns_ssrf=False)
    assert valid is True
    assert norm == "https://example.com/test"
    assert host == "example.com"
    assert port == 443
    assert scheme == "https"
    assert err is None


def test_valid_http_url():
    valid, norm, err, host, port, scheme = validate_and_normalize_url("http://example.com:8080/path", check_dns_ssrf=False)
    assert valid is True
    assert norm == "http://example.com:8080/path"
    assert host == "example.com"
    assert port == 8080
    assert scheme == "http"


def test_missing_scheme_defaults_to_https():
    valid, norm, err, host, port, scheme = validate_and_normalize_url("wikipedia.org", check_dns_ssrf=False)
    assert valid is True
    assert norm.startswith("https://wikipedia.org")
    assert host == "wikipedia.org"
    assert scheme == "https"


def test_unsupported_scheme():
    valid, _, err, _, _, _ = validate_and_normalize_url("ftp://files.example.com", check_dns_ssrf=False)
    assert valid is False
    assert "Unsupported URL scheme 'ftp'" in err


def test_empty_url():
    valid, _, err, _, _, _ = validate_and_normalize_url("", check_dns_ssrf=False)
    assert valid is False
    assert "cannot be empty" in err


def test_prohibited_localhost():
    valid, _, err, _, _, _ = validate_and_normalize_url("http://localhost:8000", check_dns_ssrf=False)
    assert valid is False
    assert "localhost is prohibited" in err


def test_prohibited_private_ip():
    # 192.168.1.1
    is_proh, reason = is_prohibited_ip("192.168.1.1")
    assert is_proh is True
    assert "Private" in reason

    valid, _, err, _, _, _ = validate_and_normalize_url("http://192.168.1.1/admin", check_dns_ssrf=False)
    assert valid is False
    assert "Target IP is prohibited" in err


def test_prohibited_loopback_and_metadata():
    # 127.0.0.1
    is_proh, _ = is_prohibited_ip("127.0.0.1")
    assert is_proh is True

    # ::1 IPv6 loopback
    is_proh_v6, _ = is_prohibited_ip("::1")
    assert is_proh_v6 is True

    # Cloud metadata
    is_proh_meta, _ = is_prohibited_ip("169.254.169.254")
    assert is_proh_meta is True
