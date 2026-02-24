"""
CloudFail v2.0 — Cloudflare IP range management & detection
"""
from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional

from cloudfail.config import (
    CF_IPS_V4_URL, CF_IPS_V6_URL, CF_SUBNET_CACHE,
    CLOUDFLARE_ASN, CLOUDFLARE_RANGES_FALLBACK,
)
from cloudfail.utils import logger


def _fetch_cf_ranges(url: str) -> List[str]:
    from cloudfail.utils.http_client import get as http_get
    resp = http_get(url, timeout=10)
    resp.raise_for_status()
    return [line.strip() for line in resp.text.splitlines() if line.strip()]


def update_cf_ranges() -> List[str]:
    """Download Cloudflare v4+v6 IP ranges, cache to disk, return list."""
    logger.info("Fetching Cloudflare IP ranges (v4 + v6)…")
    ranges: List[str] = []
    for url in (CF_IPS_V4_URL, CF_IPS_V6_URL):
        try:
            ranges.extend(_fetch_cf_ranges(url))
        except Exception as exc:
            logger.warning(f"Could not fetch {url}: {exc}")

    if ranges:
        CF_SUBNET_CACHE.write_text("\n".join(ranges) + "\n", encoding="utf-8")
        logger.success(f"Saved {len(ranges)} Cloudflare CIDR blocks to cache.")
    else:
        logger.warning(
            f"Live download failed — using {len(CLOUDFLARE_RANGES_FALLBACK)} "
            "built-in fallback ranges. Add [bold]--no-verify-ssl[/bold] if "
            "you are behind a corporate TLS-inspection proxy."
        )
        ranges = list(CLOUDFLARE_RANGES_FALLBACK)
    return ranges


def load_cf_ranges() -> List[str]:
    """Load Cloudflare CIDR blocks from cache; download or use fallback if absent."""
    if not CF_SUBNET_CACHE.exists():
        logger.info("CF subnet cache not found — downloading now…")
        return update_cf_ranges()
    ranges = [
        line.strip()
        for line in CF_SUBNET_CACHE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not ranges:
        logger.warning("Cache file empty — using built-in fallback ranges.")
        return list(CLOUDFLARE_RANGES_FALLBACK)
    return ranges


def is_cloudflare_ip(ip: str, cf_ranges: Optional[List[str]] = None) -> bool:
    """Return True if *ip* falls within any Cloudflare CIDR block."""
    if cf_ranges is None:
        cf_ranges = load_cf_ranges()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cf_ranges:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def resolve_domain(domain: str) -> Optional[str]:
    """Resolve *domain* to an IPv4 address. Returns None on failure."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def asn_for_ip(ip: str) -> str:
    """Look up the ASN for *ip* via HackerTarget. Returns e.g. 'AS13335'."""
    try:
        from cloudfail.utils.http_client import get as http_get
        resp = http_get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=8)
        if resp.status_code == 200 and "," in resp.text:
            parts = resp.text.strip().split(",")
            if len(parts) >= 2:
                return parts[1].strip().strip('"')
    except Exception:
        pass
    return "UNKNOWN"


def is_cloudflare_asn(asn: str) -> bool:
    """Return True if the ASN belongs to Cloudflare."""
    return CLOUDFLARE_ASN.upper() in asn.upper()
