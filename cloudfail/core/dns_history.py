"""
CloudFail v2.0 — DNS resolution with thread-safe retry logic
"""
from __future__ import annotations

import concurrent.futures
import socket
import time
from typing import Dict, List, Optional, Tuple

import dns.resolver
import dns.exception

from cloudfail.config import DEFAULT_THREADS
from cloudfail.utils import logger


def resolve_host(hostname: str, retries: int = 2) -> Optional[str]:
    """
    Resolve *hostname* to an IPv4 address, retrying on transient errors.
    Returns None if resolution fails.
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
    """
    Return True if the domain has a wildcard DNS entry (*.domain).
    """
    canary = f"randomxyz1234567890.{domain}"
    result = resolve_host(canary, retries=1)
    return result is not None


def resolve_bulk(
    hostnames: List[str],
    max_workers: int = DEFAULT_THREADS,
) -> Dict[str, Optional[str]]:
    """
    Resolve a list of hostnames concurrently.
    Returns a dict mapping hostname -> IP (or None).
    """
    results: Dict[str, Optional[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(resolve_host, h): h for h in hostnames
        }
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                results[host] = future.result()
            except Exception:
                results[host] = None
    return results


def passive_dns_lookup(domain: str) -> List[str]:
    """
    Attempt passive historical DNS lookup via HackerTarget's free API.
    Returns a list of historical IP addresses for the domain.
    """
    from cloudfail.utils.http_client import get as http_get

    ips: List[str] = []
    try:
        resp = http_get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10,
        )
        if resp.status_code == 200 and "," in resp.text:
            for line in resp.text.splitlines():
                parts = line.split(",")
                if len(parts) == 2:
                    ip = parts[1].strip()
                    if ip and not ip.startswith("error"):
                        ips.append(ip)
    except Exception as exc:
        logger.warning(f"[PassiveDNS] HackerTarget lookup failed: {exc}")
    return ips
