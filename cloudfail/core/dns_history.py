"""
CloudFail v2.0 — DNS resolution + multi-source passive DNS aggregation

Passive DNS sources (no API key):
  - HackerTarget  (100 free/day)
  - AlienVault OTX  (rate-limit aware with backoff)
  - ViewDNS.info IP history
  - RapidDNS passive DNS

Resolution:
  - dnspython with configurable resolvers
  - Wildcard detection via random subdomain
  - ThreadPoolExecutor bulk resolution
"""
from __future__ import annotations

import concurrent.futures
import re
import time
from typing import Dict, List, Optional, Set

import dns.exception
import dns.resolver

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
    resolver.timeout = 3.0

    for attempt in range(retries + 1):
        try:
            for rdata in resolver.resolve(hostname, "A"):
                return str(rdata)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except (dns.resolver.Timeout, dns.exception.DNSException):
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
    return None


def check_wildcard(domain: str) -> bool:
    """Return True if *.domain resolves (wildcard DNS active)."""
    probe = f"randomxyz1234567890cfnotreal.{domain}"
    return resolve_host(probe, retries=1) is not None


def resolve_bulk(
    hostnames: List[str],
    max_workers: int = DEFAULT_THREADS,
) -> Dict[str, Optional[str]]:
    """Resolve a list of hostnames concurrently. Returns {hostname: ip_or_None}."""
    results: Dict[str, Optional[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fmap = {ex.submit(resolve_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(fmap):
            host = fmap[future]
            try:
                results[host] = future.result()
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
                    if ip and "." in ip and ip[0].isdigit():
                        ips.append(ip)
        elif text.startswith("error"):
            logger.warning(
                f"[PassiveDNS/HackerTarget] {text[:120]} "
                "(Daily limit reached. Get a free API key at hackertarget.com)"
            )
    except Exception as exc:
        logger.warning(f"[PassiveDNS/HackerTarget] {exc}")
        logger.debug_exc(exc, "HackerTarget")
    return ips


def _alienvault_otx(domain: str) -> List[str]:
    """
    AlienVault OTX passive DNS — free, no API key needed.
    Implements 429 detection with exponential backoff (up to 3 retries).
    Falls back gracefully if rate limited.
    """
    from cloudfail.utils.http_client import get as http_get
    ips: List[str] = []

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    for attempt in range(3):
        try:
            resp = http_get(url, timeout=20)

            if resp.status_code == 200:
                for entry in resp.json().get("passive_dns", []):
                    addr = entry.get("address", "").strip()
                    # IPv4 only (skip IPv6)
                    if addr and "." in addr and ":" not in addr:
                        ips.append(addr)
                return ips

            elif resp.status_code == 429:
                if attempt < 2:
                    wait = 2 ** (attempt + 2)   # 4s, 8s
                    logger.warning(
                        f"[PassiveDNS/AlienVault] Rate limited (429) — "
                        f"waiting {wait}s before retry {attempt + 2}/3"
                    )
                    time.sleep(wait)
                else:
                    logger.warning(
                        "[PassiveDNS/AlienVault] Rate limit persists — skipping OTX."
                    )
                    return []

            else:
                logger.warning(f"[PassiveDNS/AlienVault] HTTP {resp.status_code}")
                return []

        except Exception as exc:
            logger.warning(f"[PassiveDNS/AlienVault] {exc}")
            logger.debug_exc(exc, "AlienVault OTX")
            return []

    return ips


def _viewdns(domain: str) -> List[str]:
    """ViewDNS.info IP History — free, no key, HTML regex extraction."""
    from cloudfail.utils.http_client import get as http_get
    ips: List[str] = []
    try:
        resp = http_get(
            f"https://viewdns.info/iphistory/?domain={domain}",
            headers={"Accept": "text/html"},
            timeout=15,
        )
        if resp.status_code == 200:
            found = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", resp.text)
            for ip in found:
                if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                    ips.append(ip)
    except Exception as exc:
        logger.warning(f"[PassiveDNS/ViewDNS] {exc}")
        logger.debug_exc(exc, "ViewDNS")
    return ips


def _rapiddns_passive(domain: str) -> List[str]:
    """RapidDNS same-IP lookup for passive IP discovery."""
    from cloudfail.utils.http_client import get as http_get
    ips: List[str] = []
    try:
        resp = http_get(
            f"https://rapiddns.io/subdomain/{domain}?full=1&down=1",
            headers={"Accept": "text/html,application/xhtml+xml"},
            timeout=20,
        )
        if resp.status_code == 200:
            found = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", resp.text)
            for ip in found:
                if ip and not ip.startswith(("127.", "10.", "192.168.", "172.")):
                    ips.append(ip)
    except Exception as exc:
        logger.warning(f"[PassiveDNS/RapidDNS] {exc}")
        logger.debug_exc(exc, "RapidDNS passive")
    return ips


# ---------------------------------------------------------------------------
# Combined passive DNS aggregation
# ---------------------------------------------------------------------------

def passive_dns_lookup(domain: str) -> List[str]:
    """
    Aggregate historical IPs for *domain* from multiple free passive DNS sources.

    Sources queried concurrently:
      - HackerTarget   (100 free/day)
      - AlienVault OTX (free, rate-limit aware)
      - ViewDNS.info   (free, no key)
      - RapidDNS       (free, no key)

    Returns deduplicated list of IPv4 strings.
    """
    all_ips: Set[str] = set()

    sources = {
        "HackerTarget": _hackertarget,
        "AlienVault":   _alienvault_otx,
        "ViewDNS":      _viewdns,
        "RapidDNS":     _rapiddns_passive,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        fmap = {ex.submit(fn, domain): name for name, fn in sources.items()}
        for future in concurrent.futures.as_completed(fmap):
            src = fmap[future]
            try:
                result = future.result()
                all_ips.update(result)
            except Exception as exc:
                logger.warning(f"[PassiveDNS/{src}] Error: {exc}")
                logger.debug_exc(exc, src)

    # Reverse IP pivot on first non-CF IP to find co-hosted domains
    from cloudfail.core.cloudflare import is_cloudflare_ip
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
