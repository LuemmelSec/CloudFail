"""
CloudFail v2.0 — DNSDumpster scraper with proper CSRF token handling

DNSDumpster uses Django's CSRF protection:
  1. GET the homepage to receive the csrftoken cookie + hidden form field
  2. POST with that token in both the cookie and the form body
  3. Parse the result HTML for DNS/MX/Host record tables

This replaces the broken 2018 DNSDumpsterAPI.py which didn't handle
the CSRF flow correctly after DNSDumpster updated their site.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

import cloudfail.config as _cfg
from cloudfail.utils import logger


# DNSDumpster uses its own session for the CSRF dance,
# so we build one from our http_client's base but manage
# cookies explicitly.

BASE_URL = "https://dnsdumpster.com/"


def _make_session() -> "requests.Session":
    """Build a requests session that mirrors our SSL_VERIFY setting."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.verify = _cfg.SSL_VERIFY
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    })
    return s


def _extract_csrf(html: str, cookies: dict) -> Optional[str]:
    """
    Extract CSRF token from the hidden form field first,
    falling back to the csrftoken cookie.
    """
    # Django embeds the token in a hidden input
    m = re.search(
        r'<input[^>]+name=["\']csrfmiddlewaretoken["\'][^>]+value=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if m:
        return m.group(1)
    # Fallback: read from cookie jar
    return cookies.get("csrftoken")


def _parse_ip_rows(html: str) -> List[Dict[str, str]]:
    """
    Parse DNSDumpster result tables and extract records containing IPs.

    DNSDumpster renders rows as:
      <td class="col-md-4">HOSTNAME</td>
      <td class="col-md-2">IP</td>
      <td class="col-md-3">COUNTRY / AS / PROVIDER</td>
      <td class="col-md-3">REVERSE DNS</td>

    We extract all rows that contain a valid IPv4 address in the second td.
    """
    results: List[Dict[str, str]] = []
    seen_ips: Set[str] = set()

    # Match table rows
    row_pattern = re.compile(r'<tr[^>]*>(.*?)</tr>', re.DOTALL | re.IGNORECASE)
    td_pattern  = re.compile(r'<td[^>]*>(.*?)</td>', re.DOTALL | re.IGNORECASE)
    ip_pattern  = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    tag_strip   = re.compile(r'<[^>]+>')

    for row_m in row_pattern.finditer(html):
        row_html = row_m.group(1)
        tds = [tag_strip.sub('', td.group(1)).strip()
               for td in td_pattern.finditer(row_html)]

        if len(tds) < 2:
            continue

        # Find first td that contains an IP
        for td_text in tds:
            ip_m = ip_pattern.search(td_text)
            if ip_m:
                ip = ip_m.group(1)
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    # Determine record type from context
                    record_type = "HOST"
                    if "MX" in row_html.upper() or any("mail" in t.lower() for t in tds):
                        record_type = "MX"
                    elif len(tds) >= 1 and "." in tds[0] and not tds[0].startswith("1"):
                        record_type = "DNS"

                    results.append({
                        "ip":       ip,
                        "hostname": tds[0] if tds else "",
                        "provider": tds[2] if len(tds) > 2 else "",
                        "type":     record_type,
                    })
                break

    return results


def query(domain: str) -> List[Dict[str, str]]:
    """
    Query DNSDumpster for all DNS records associated with *domain*.

    Returns a list of dicts:
      {"ip": str, "hostname": str, "provider": str, "type": "HOST"|"MX"|"DNS"}

    Returns [] on any failure — caller should treat this as best-effort.
    """
    logger.info(f"[DNSDumpster] Querying DNS records for {domain}…")
    session = _make_session()

    # ── Step 1: GET homepage to collect CSRF token ───────────────────────
    try:
        r1 = session.get(BASE_URL, timeout=15)
        r1.raise_for_status()
    except Exception as exc:
        logger.warning(f"[DNSDumpster] Could not reach homepage: {exc}")
        return []

    csrf_token = _extract_csrf(r1.text, dict(r1.cookies))
    if not csrf_token:
        logger.warning("[DNSDumpster] Could not extract CSRF token from homepage.")
        return []

    # ── Step 2: POST with CSRF token and target domain ───────────────────
    try:
        r2 = session.post(
            BASE_URL,
            data={
                "csrfmiddlewaretoken": csrf_token,
                "targetip":           domain,
                "user":               "free",
            },
            headers={
                "Referer":       BASE_URL,
                "Origin":        "https://dnsdumpster.com",
                "Content-Type":  "application/x-www-form-urlencoded",
            },
            timeout=20,
        )
        r2.raise_for_status()
    except Exception as exc:
        logger.warning(f"[DNSDumpster] POST failed: {exc}")
        return []

    # ── Step 3: Parse results ────────────────────────────────────────────
    if "records found" not in r2.text and "table" not in r2.text.lower():
        logger.warning(
            "[DNSDumpster] Response does not contain expected result tables. "
            "The site may have changed its layout."
        )
        return []

    records = _parse_ip_rows(r2.text)
    logger.info(f"[DNSDumpster] Found {len(records)} records with IPs.")
    return records


def get_ips(domain: str) -> List[str]:
    """
    Convenience wrapper — return just the IP strings from a DNSDumpster query.
    """
    return [r["ip"] for r in query(domain)]
