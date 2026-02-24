"""
CloudFail v2.0 — ASN lookup and filtering logic
"""
from __future__ import annotations

import concurrent.futures
from typing import Dict, List, Optional, Tuple

from cloudfail.config import CLOUDFLARE_ASN, DEFAULT_THREADS
from cloudfail.utils import logger


def asn_for_ip(ip: str) -> str:
    """
    Query HackerTarget for the ASN of *ip*.
    Returns a string like 'AS13335' or 'UNKNOWN'.
    """
    try:
        from cloudfail.utils.http_client import get as http_get
        resp = http_get(
            f"https://api.hackertarget.com/aslookup/?q={ip}",
            timeout=8,
        )
        if resp.status_code == 200 and "," in resp.text:
            # Format: "IP","ASN","CIDR","Name","Country"
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
    max_workers: int = min(DEFAULT_THREADS, 5),  # be gentle on free API
) -> List[Dict[str, str]]:
    """
    For each IP, look up its ASN and check Cloudflare membership.

    Returns a list of dicts:
      {
        "ip": str,
        "asn": str,
        "is_cloudflare": "yes" | "no" | "likely",
        "confidence": int  0-100
      }
    """
    from cloudfail.core.cloudflare import is_cloudflare_ip

    enriched: List[Dict[str, str]] = []

    def _process(ip: str) -> Dict[str, str]:
        asn = asn_for_ip(ip)
        in_range = is_cloudflare_ip(ip, cf_ranges)
        asn_cf = is_cloudflare_asn(asn)

        if in_range and asn_cf:
            status, confidence = "yes", 99
        elif in_range or asn_cf:
            status, confidence = "likely", 70
        else:
            status, confidence = "no", 90
        return {"ip": ip, "asn": asn, "is_cloudflare": status, "confidence": str(confidence)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            try:
                enriched.append(future.result())
            except Exception as exc:
                ip = futures[future]
                logger.warning(f"ASN enrichment failed for {ip}: {exc}")
                enriched.append({"ip": ip, "asn": "UNKNOWN", "is_cloudflare": "unknown", "confidence": "0"})

    return enriched
