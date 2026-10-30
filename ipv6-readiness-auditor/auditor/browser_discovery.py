"""
Browser-Based Resource Discovery Module.
Uses Playwright Chromium to load target pages in headless mode and capture
all loaded network resources, scripts, stylesheets, images, APIs, fonts, and third parties.
Includes fallback static discovery if Playwright browser is unavailable in the environment.
"""

import re
import time
from urllib.parse import urlparse
from typing import Dict, Any, List, Set, Optional, Callable


def is_third_party(target_host: str, resource_host: str) -> bool:
    """
    Checks if a resource host is third-party relative to target host.
    e.g., example.com vs cdn.example.com is first-party.
    example.com vs cdn.cloudflare.com is third-party.
    """
    target = target_host.lower().strip(".")
    res = resource_host.lower().strip(".")

    if target == res:
        return False

    # Check if subdomain
    if res.endswith("." + target):
        return False

    # Handle www striping
    target_clean = re.sub(r"^www\.", "", target)
    res_clean = re.sub(r"^www\.", "", res)

    if res_clean == target_clean or res_clean.endswith("." + target_clean):
        return False

    return True


def discover_resources_playwright(
    url: str,
    timeout_ms: int = 20000,
    status_callback: Optional[Callable[[str], None]] = None
) -> Dict[str, Any]:
    """
    Launches headless Chromium using Playwright to discover all active network dependencies.
    """
    from playwright.sync_api import sync_playwright, Error as PlaywrightError

    target_host = urlparse(url).hostname or ""
    resources_map: Dict[str, Dict[str, Any]] = {}
    page_title = ""
    browser_error = None

    if status_callback:
        status_callback("Launching Playwright Chromium browser...")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=False,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 (IPv6ReadinessAuditor/1.0)",
                viewport={"width": 1280, "height": 720}
            )
            page = context.new_page()

            def on_request(request):
                res_url = request.url
                parsed = urlparse(res_url)
                host = parsed.hostname or ""
                if not host or parsed.scheme not in ("http", "https"):
                    return

                if res_url not in resources_map:
                    resources_map[res_url] = {
                        "url": res_url,
                        "hostname": host,
                        "resource_type": request.resource_type or "other",
                        "method": request.method,
                        "status_code": None,
                        "success": False,
                        "failure_message": None,
                        "is_third_party": is_third_party(target_host, host),
                        "observed_in_browser": True,
                        "request_count": 1,
                        "start_time": time.perf_counter(),
                        "duration_ms": 0.0,
                    }
                else:
                    resources_map[res_url]["request_count"] += 1

            def on_response(response):
                res_url = response.url
                if res_url in resources_map:
                    item = resources_map[res_url]
                    item["status_code"] = response.status
                    item["success"] = response.ok
                    item["duration_ms"] = round((time.perf_counter() - item["start_time"]) * 1000, 2)

            def on_request_failed(request):
                res_url = request.url
                if res_url in resources_map:
                    item = resources_map[res_url]
                    failure = request.failure
                    item["success"] = False
                    item["failure_message"] = failure if isinstance(failure, str) else (failure.get("errorText") if isinstance(failure, dict) else str(failure))
                    item["duration_ms"] = round((time.perf_counter() - item["start_time"]) * 1000, 2)

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("requestfailed", on_request_failed)

            if status_callback:
                status_callback(f"Loading {url} and capturing network requests...")

            try:
                page.goto(url, wait_until="load", timeout=timeout_ms)
                # Brief wait for dynamic asynchronous assets
                page.wait_for_timeout(2000)
                page_title = page.title()
            except PlaywrightError as e:
                browser_error = f"Browser page load warning/timeout: {str(e)}"
            finally:
                browser.close()

    except Exception as e:
        browser_error = f"Playwright execution error: {str(e)}"

    resources_list = list(resources_map.values())
    unique_hosts = sorted(list(set(r["hostname"] for r in resources_list if r["hostname"])))

    return {
        "success": len(resources_list) > 0,
        "discovery_method": "Playwright Headless Chromium",
        "page_title": page_title,
        "browser_error": browser_error,
        "resources": resources_list,
        "unique_hosts": unique_hosts,
        "total_requests": sum(r["request_count"] for r in resources_list),
        "total_unique_resources": len(resources_list),
    }


def discover_resources_fallback(
    url: str,
    timeout: float = 10.0,
    status_callback: Optional[Callable[[str], None]] = None
) -> Dict[str, Any]:
    """
    Fallback resource discovery using direct HTTP GET and HTML tag parsing
    when Playwright browser binaries are not installed or prohibited in the host environment.
    """
    import requests
    from urllib.parse import urljoin

    target_host = urlparse(url).hostname or ""
    resources_map: Dict[str, Dict[str, Any]] = {}
    page_title = ""
    error_msg = None

    if status_callback:
        status_callback(f"Running fallback HTML parser for {url}...")

    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (IPv6ReadinessAuditor/1.0)"})
        html = resp.text

        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if title_match:
            page_title = title_match.group(1).strip()

        # Add the main document itself
        resources_map[url] = {
            "url": url,
            "hostname": target_host,
            "resource_type": "document",
            "method": "GET",
            "status_code": resp.status_code,
            "success": resp.ok,
            "failure_message": None,
            "is_third_party": False,
            "observed_in_browser": False,
            "request_count": 1,
            "duration_ms": round(resp.elapsed.total_seconds() * 1000, 2),
        }

        # Match script src, link href, img src, source src, iframe src
        patterns = [
            (r'<script[^>]+src=["\'](.*?)["\']', "script"),
            (r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\'](.*?)["\']', "stylesheet"),
            (r'<link[^>]+href=["\'](.*?)["\'][^>]+rel=["\']stylesheet["\']', "stylesheet"),
            (r'<img[^>]+src=["\'](.*?)["\']', "image"),
            (r'<source[^>]+src=["\'](.*?)["\']', "media"),
            (r'<iframe[^>]+src=["\'](.*?)["\']', "document"),
        ]

        for pat, rtype in patterns:
            for match in re.findall(pat, html, re.IGNORECASE):
                full_url = urljoin(url, match)
                parsed = urlparse(full_url)
                host = parsed.hostname or ""
                if host and parsed.scheme in ("http", "https") and full_url not in resources_map:
                    resources_map[full_url] = {
                        "url": full_url,
                        "hostname": host,
                        "resource_type": rtype,
                        "method": "GET",
                        "status_code": 200,
                        "success": True,
                        "failure_message": None,
                        "is_third_party": is_third_party(target_host, host),
                        "observed_in_browser": False,
                        "request_count": 1,
                        "duration_ms": 0.0,
                    }

    except Exception as e:
        error_msg = f"Fallback discovery error: {str(e)}"

    resources_list = list(resources_map.values())
    unique_hosts = sorted(list(set(r["hostname"] for r in resources_list if r["hostname"])))

    return {
        "success": len(resources_list) > 0,
        "discovery_method": "Static HTML Resource Discovery (Fallback)",
        "page_title": page_title,
        "browser_error": error_msg,
        "resources": resources_list,
        "unique_hosts": unique_hosts,
        "total_requests": len(resources_list),
        "total_unique_resources": len(resources_list),
    }


def discover_resources(
    url: str,
    timeout_ms: int = 20000,
    status_callback: Optional[Callable[[str], None]] = None
) -> Dict[str, Any]:
    """
    High-level entry point: Attempts Playwright Chromium discovery,
    falling back cleanly to static HTML discovery if Playwright fails or isn't installed.
    """
    try:
        import playwright
        result = discover_resources_playwright(url, timeout_ms=timeout_ms, status_callback=status_callback)
        if result["success"]:
            return result
        # If Playwright completed with 0 resources or error, try fallback
        if status_callback:
            status_callback("Playwright returned no resources. Trying fallback discovery...")
        fallback = discover_resources_fallback(url, timeout=10.0, status_callback=status_callback)
        if fallback["success"]:
            fallback["browser_error"] = f"Playwright Note: {result.get('browser_error') or 'No resources captured; switched to fallback'}"
            return fallback
        return result
    except Exception as e:
        if status_callback:
            status_callback(f"Playwright not ready ({e}). Falling back to static discovery...")
        return discover_resources_fallback(url, timeout=10.0, status_callback=status_callback)
