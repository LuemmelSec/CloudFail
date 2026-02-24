"""
CloudFail v2.0 — DNS resolution with thread-safe retry logic + passive DNS
"""
from __future__ import annotations

import concurrent.futures
import time
from typing import Dict, List, Optional

import dns.resolver
import dns.exception

from cloudfail.config import DEFAULT_THREADS
from cloudfail.utils import logger


def resolve_host(hostname: str, retries: int = 2) -> Optional[str]:
    """
    Resolve *hostname* to its first IPv4 address.
    Retries on transient DNS errors. Returns None on permanent failure.
    """
    hostname = hostname.strip()
    if not hostname:
        return None

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.lifetime = 5.0

    for attempt in range(retries + 1):
        try:
            answers = resolver.resolve(hostname, "A")
            for rdata in answers:
                return str(rdata)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.resolver.Timeout, dns.exception.DNSException):
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
    return None


def check_wildcard(domain: str) -> bool:
    """Return True if the domain has a wildcard DNS entry (*.domain resolves)."""
    canary = f"randomxyz1234567890cf.{domain}"
    return resolve_host(canary, retries=1) is not None


def resolve_bulk(
    hostnames: List[str],
    max_workers: int = DEFAULT_THREADS,
) -> Dict[str, Optional[str]]:
    """
    Resolve a list of hostnames concurrently.
    Returns dict mapping hostname -> IP string (or None if unresolvable).
    """
    results: Dict[str, Optional[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(resolve_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                results[host] = future.result()
            except Exception:
                results[host] = None
    return results


def passive_dns_lookup(domain: str) -> List[str]:
    """
    Collect historical IPs for *domain* using free passive DNS sources.

    Sources:
      1. HackerTarget hostsearch — returns all known subdomains + IPs
      2. HackerTarget reverseiplookup on first NON-Cloudflare IP found
         (skips CF IPs to avoid wasting quota on useless lookups)

    Returns a deduplicated list of IP strings.
    """
    from cloudfail.utils.http_client import get as http_get
    from cloudfail.core.cloudflare import is_cloudflare_ip

    ips: List[str] = []

    # Source 1: hostsearch
    try:
        resp = http_get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15,
        )
        if resp.status_code == 200 and "," in resp.text:
            for line in resp.text.splitlines():
                parts = line.split(",")
                if len(parts) == 2:
                    ip = parts[1].strip()
                    if ip and not ip.startswith("error") and "." in ip:
                        ips.append(ip)
    except Exception as exc:
        logger.warning(f"[PassiveDNS] HackerTarget hostsearch failed: {exc}")

    # Source 2: reverse IP lookup — only on the first non-CF IP to avoid waste
    pivot_ip = next((ip for ip in ips if not is_cloudflare_ip(ip)), None)
    if pivot_ip:
        try:
            resp2 = http_get(
                f"https://api.hackertarget.com/reverseiplookup/?q={pivot_ip}",
                timeout=15,
            )
            if resp2.status_code == 200 and not resp2.text.strip().startswith("error"):
                for line in resp2.text.splitlines():
                    name = line.strip()
                    if name and domain in name:
                        resolved = resolve_host(name, retries=1)
                        if resolved and resolved not in ips:
                            ips.append(resolved)
        except Exception:
            pass  # Reverse lookup is best-effort

    unique = list(dict.fromkeys(ips))  # deduplicate, preserve order
    if unique:
        logger.info(f"[PassiveDNS] Found {len(unique)} historical IPs.")
    return unique
