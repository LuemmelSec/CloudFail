"""
CloudFail v2.0 — DNS resolution + multi-source passive DNS aggregation
"""
from __future__ import annotations

import concurrent.futures
import time
from typing import Dict, List, Optional, Set

import dns.resolver
import dns.exception

from cloudfail.config import DEFAULT_THREADS
from cloudfail.utils import logger


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve_host(hostname: str, retries: int = 2) -> Optional[str]:
    """Resolve hostname to IPv4. Returns None on permanent failure."""
    hostname = hostname.strip()
    if not hostname:
        return None
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.lifetime = 5.0
    for attempt in range(retries + 1):
        try:
            for rdata in resolver.resolve(hostname, "A"):
                return str(rdata)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.resolver.Timeout, dns.exception.DNSException):
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
    return None


def check_wildcard(domain: str) -> bool:
    """Return True if *.domain resolves (wildcard DNS)."""
    return resolve_host(f"randomxyz1234567890cf.{domain}", retries=1) is not None


def resolve_bulk(
    hostnames: List[str],
    max_workers: int = DEFAULT_THREADS,
) -> Dict[str, Optional[str]]:
    """Resolve a list of hostnames concurrently."""
    results: Dict[str, Optional[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fmap = {ex.submit(resolve_host, h): h for h in hostnames}
        for f in concurrent.futures.as_completed(fmap):
            host = fmap[f]
            try:
                results[host] = f.result()
            except Exception:
                results[host] = None
    return results


# ---------------------------------------------------------------------------
# Passive DNS sources
# ---------------------------------------------------------------------------

def _hackertarget(domain: str) -> List[str]:
    """HackerTarget hostsearch — 100 free queries/day."""
    from cloudfail.utils.http_client import get as http_get
    ips: List[str] = []
    try:
        resp = http_get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15,
        )
        text = resp.text.strip()
        if resp.status_code == 200 and "," in text and not text.startswith("error"):
            for line in text.splitlines():
                parts = line.split(",")
                if len(parts) == 2:
                    ip = parts[1].strip()
                    if ip and "." in ip:
                        ips.append(ip)
        elif text.startswith("error"):
            logger.warning(
                f"[PassiveDNS/HackerTarget] {text[:120]} "
                "(Daily limit: 100 queries. Get a free API key at hackertarget.com to raise it.)"
            )
    except Exception as exc:
        logger.warning(f"[PassiveDNS/HackerTarget] {exc}")
    return ips


def _alienvault(domain: str) -> List[str]:
    """AlienVault OTX passive DNS — free, no API key needed."""
    from cloudfail.utils.http_client import get as http_get
    ips: List[str] = []
    try:
        resp = http_get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=20,
        )
        if resp.status_code == 200:
            for entry in resp.json().get("passive_dns", []):
                addr = entry.get("address", "").strip()
                # Only include IPv4 addresses
                if addr and "." in addr and ":" not in addr:
                    ips.append(addr)
        else:
            logger.warning(f"[PassiveDNS/AlienVault] HTTP {resp.status_code}")
    except Exception as exc:
        logger.warning(f"[PassiveDNS/AlienVault] {exc}")
    return ips


def _viewdns(domain: str) -> List[str]:
    """ViewDNS.info IP History — free, no key, HTML parse."""
    from cloudfail.utils.http_client import get as http_get
    import re
    ips: List[str] = []
    try:
        resp = http_get(
            f"https://viewdns.info/iphistory/?domain={domain}",
            headers={"Accept": "text/html"},
            timeout=15,
        )
        if resp.status_code == 200:
            # Extract IPs from the HTML table
            found = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
            for ip in found:
                # Filter out obviously internal/loopback IPs
                if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                    ips.append(ip)
    except Exception as exc:
        logger.warning(f"[PassiveDNS/ViewDNS] {exc}")
    return ips


# ---------------------------------------------------------------------------
# Combined passive DNS aggregation
# ---------------------------------------------------------------------------

def passive_dns_lookup(domain: str) -> List[str]:
    """
    Aggregate historical IPs for *domain* from multiple free passive DNS sources.

    Sources queried concurrently:
      - HackerTarget (100 free/day)
      - AlienVault OTX (free, no key)
      - ViewDNS.info IP history (free, no key)

    Returns deduplicated list of IPv4 strings, CF IPs excluded from pivot.
    """
    from cloudfail.core.cloudflare import is_cloudflare_ip

    all_ips: Set[str] = set()

    sources = {
        "hackertarget": _hackertarget,
        "alienvault":   _alienvault,
        "viewdns":      _viewdns,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        fmap = {ex.submit(fn, domain): name for name, fn in sources.items()}
        for f in concurrent.futures.as_completed(fmap):
            src = fmap[f]
            try:
                result = f.result()
                all_ips.update(result)
            except Exception as exc:
                logger.warning(f"[PassiveDNS/{src}] Error: {exc}")

    # Reverse IP lookup on first non-CF IP to find co-hosted domains
    pivot_ip = next((ip for ip in all_ips if not is_cloudflare_ip(ip)), None)
    if pivot_ip:
        from cloudfail.utils.http_client import get as http_get
        try:
            resp = http_get(
                f"https://api.hackertarget.com/reverseiplookup/?q={pivot_ip}",
                timeout=15,
            )
            text = resp.text.strip()
            if resp.status_code == 200 and not text.startswith("error"):
                for line in text.splitlines():
                    name = line.strip()
                    if name and domain in name:
                        resolved = resolve_host(name, retries=1)
                        if resolved:
                            all_ips.add(resolved)
        except Exception:
            pass

    unique = list(dict.fromkeys(all_ips))
    if unique:
        logger.info(f"[PassiveDNS] Aggregated {len(unique)} unique historical IPs.")
    else:
        logger.warning("[PassiveDNS] No historical IPs found across all sources.")
    return unique
