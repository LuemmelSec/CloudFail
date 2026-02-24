"""
CloudFail v2.0 — ASN lookup and IP enrichment
"""
from __future__ import annotations

import concurrent.futures
from typing import Dict, List, Optional

from cloudfail.config import CLOUDFLARE_ASN, DEFAULT_THREADS
from cloudfail.utils import logger


def asn_for_ip(ip: str) -> str:
    """
    Query HackerTarget for the ASN of *ip*.
    Returns a string like 'AS13335' or 'UNKNOWN'.
    HackerTarget free tier: 100 queries/day.
    """
    try:
        from cloudfail.utils.http_client import get as http_get
        resp = http_get(
            f"https://api.hackertarget.com/aslookup/?q={ip}",
            timeout=10,
        )
        if resp.status_code == 200 and "," in resp.text:
            parts = resp.text.strip().split(",")
            if len(parts) >= 2:
                return parts[1].strip().strip('"')
    except Exception:
        pass
    return "UNKNOWN"


def is_cloudflare_asn(asn: str) -> bool:
    """Return True if the given ASN string belongs to Cloudflare."""
    return CLOUDFLARE_ASN.upper() in asn.upper()


def enrich_ips(
    ips: List[str],
    cf_ranges: Optional[List[str]] = None,
    max_workers: int = 5,
) -> List[Dict[str, str]]:
    """
    For each IP, look up its ASN and check Cloudflare membership.
    Only non-Cloudflare IPs (by range) are ASN-enriched to conserve API quota.

    Returns list of dicts:
      {"ip": str, "asn": str, "is_cloudflare": "yes"|"no"|"likely"|"unknown",
       "confidence": str}
    """
    from cloudfail.core.cloudflare import is_cloudflare_ip

    enriched: List[Dict[str, str]] = []

    cf_ips = [ip for ip in ips if is_cloudflare_ip(ip, cf_ranges)]
    non_cf_ips = [ip for ip in ips if not is_cloudflare_ip(ip, cf_ranges)]

    # CF range hits — mark directly without burning API quota
    for ip in cf_ips:
        enriched.append({
            "ip": ip,
            "asn": CLOUDFLARE_ASN,
            "is_cloudflare": "yes",
            "confidence": "95",
        })

    # Non-CF IPs — do ASN lookup to double-check
    def _process(ip: str) -> Dict[str, str]:
        asn = asn_for_ip(ip)
        if is_cloudflare_asn(asn):
            # ASN says CF but range didn't match — likely a new range or proxy
            return {"ip": ip, "asn": asn, "is_cloudflare": "likely", "confidence": "70"}
        return {"ip": ip, "asn": asn, "is_cloudflare": "no", "confidence": "90"}

    if non_cf_ips:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_process, ip): ip for ip in non_cf_ips}
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    enriched.append(future.result())
                except Exception as exc:
                    logger.warning(f"[ASN] Enrichment failed for {ip}: {exc}")
                    enriched.append({
                        "ip": ip,
                        "asn": "UNKNOWN",
                        "is_cloudflare": "unknown",
                        "confidence": "0",
                    })

    return enriched
