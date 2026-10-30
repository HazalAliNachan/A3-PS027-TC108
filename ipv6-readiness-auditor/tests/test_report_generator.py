"""
Unit tests for report generation (JSON, CSV, HTML).
"""

import json
from auditor.report_generator import generate_json_report, generate_csv_report, generate_html_report


def test_generate_json_report():
    sample_data = {
        "target_url": "https://example.com",
        "target_host": "example.com",
        "resources": [{"url": "https://example.com/logo.png", "hostname": "example.com"}],
        "hosts": {},
        "findings": [],
        "assessment": {"overall_score": 90.0, "overall_category": "Partial"}
    }
    json_out = generate_json_report(sample_data)
    parsed = json.loads(json_out)
    assert parsed["target_host"] == "example.com"
    assert len(parsed["resources"]) == 1


def test_generate_csv_report():
    sample_data = {
        "target_url": "https://example.com",
        "resources": [
            {
                "url": "https://example.com/style.css",
                "hostname": "example.com",
                "resource_type": "stylesheet",
                "is_third_party": False,
                "method": "GET",
                "status_code": 200,
                "observed_in_browser": True,
                "duration_ms": 45.2
            }
        ],
        "hosts": {
            "example.com": {
                "dns": {"ipv4_addresses": ["93.184.216.34"], "ipv6_addresses": ["2606:2800::1"]},
                "v4_tcp": {"success": True},
                "v6_tcp": {"success": True}
            }
        }
    }
    csv_out = generate_csv_report(sample_data)
    assert "Resource URL" in csv_out
    assert "example.com/style.css" in csv_out
    assert "93.184.216.34" in csv_out


def test_generate_html_report():
    sample_data = {
        "target_url": "https://example.com",
        "target_host": "example.com",
        "assessment": {"overall_score": 85.0, "overall_category": "Partial IPv6 readiness"},
        "findings": [
            {
                "hostname": "cdn.example.com",
                "stage": "DNS Resolution",
                "observed_failure": "No AAAA record",
                "evidence": "NODATA",
                "confidence": "High",
                "recommendation": "Add AAAA"
            }
        ],
        "hosts": {},
        "resources": []
    }
    html_out = generate_html_report(sample_data)
    assert "<!DOCTYPE html>" in html_out
    assert "example.com" in html_out
    assert "cdn.example.com" in html_out
    assert "No AAAA record" in html_out


def test_empty_reports_do_not_crash():
    empty_data = {}
    json_out = generate_json_report(empty_data)
    csv_out = generate_csv_report(empty_data)
    html_out = generate_html_report(empty_data)

    assert json_out.startswith("{")
    assert "Resource URL" in csv_out
    assert "<!DOCTYPE html>" in html_out
