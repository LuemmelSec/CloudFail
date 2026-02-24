"""
CloudFail v2.0 — Certificate Transparency log pivot (crt.sh + Censys)
"""
from __future__ import annotations

import socket
from typing import List, Optional, Set

from cloudfail.utils import logger, http_client
from cloudfail.config import CRTSH_URL


# ---------------------------------------------------------------------------
# crt.sh
# ---------------------------------------------------------------------------

def crtsh_subdomains(domain: str) -> List[str]:
    """
    Query crt.sh for all certificate SANs / common names for *domain*.
    Returns a deduplicated list of hostnames.
    """
    logger.info(f"[crt.sh] Querying certificate transparency logs for {domain}…")
    found: Set[str] = set()
    url = CRTSH_URL.format(domain=domain)
    try:
        resp = http_client.get(url, timeout=20)
        if resp.status_code != 200:
            logger.warning(f"[crt.sh] HTTP {resp.status_code}")
            return []
        entries = resp.json()
        for entry in entries:
            # Each entry may have comma-separated names
            name_value: str = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name:
                    found.add(name.lower())
    except Exception as exc:
        logger.warning(f"[crt.sh] Error: {exc}")
    logger.info(f"[crt.sh] Found {len(found)} unique names.")
    return sorted(found)


# ---------------------------------------------------------------------------
# Censys v2
# ---------------------------------------------------------------------------

def censys_hosts(
    domain: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
) -> List[str]:
    """
    Search Censys v2 API for hosts serving certificates matching *domain*.
    Returns a list of IP addresses.
    """
    if not (api_id and api_secret):
        return []

    logger.info(f"[Censys] Searching for hosts matching {domain}…")
    ips: List[str] = []
    try:
        from censys.search import CensysHosts  # type: ignore

        h = CensysHosts(api_id=api_id, api_secret=api_secret)
        query = f'services.tls.certificates.leaf_data.names: "{domain}"'
        for page in h.search(query, per_page=100, pages=3):
            for host in page:
                ip = host.get("ip")
                if ip:
                    ips.append(ip)
    except ImportError:
        logger.warning("[Censys] censys package not installed. Skipping.")
    except Exception as exc:
        logger.warning(f"[Censys] Error: {exc}")

    logger.info(f"[Censys] Found {len(ips)} host IPs.")
    return ips


# ---------------------------------------------------------------------------
# Shodan (optional)
# ---------------------------------------------------------------------------

def shodan_hosts(domain: str, api_key: Optional[str] = None) -> List[str]:
    """
    Use Shodan to find IPs hosting *domain* in their SSL/TLS cert.
    Returns a list of IP strings.
    """
    if not api_key:
        return []

    logger.info(f"[Shodan] Searching for hosts matching {domain}…")
    ips: List[str] = []
    try:
        import shodan  # type: ignore

        api = shodan.Shodan(api_key)
        results = api.search(f"ssl.cert.subject.cn:{domain}")
        for match in results.get("matches", []):
            ip = match.get("ip_str")
            if ip:
                ips.append(ip)
    except ImportError:
        logger.warning("[Shodan] shodan package not installed. Skipping.")
    except Exception as exc:
        logger.warning(f"[Shodan] Error: {exc}")

    logger.info(f"[Shodan] Found {len(ips)} host IPs.")
    return ips


# ---------------------------------------------------------------------------
# SecurityTrails (optional)
# ---------------------------------------------------------------------------

def securitytrails_subdomains(domain: str, api_key: Optional[str] = None) -> List[str]:
    """
    Query SecurityTrails API for subdomains of *domain*.
    Returns a list of FQDNs.
    """
    if not api_key:
        return []

    logger.info(f"[SecurityTrails] Querying subdomains for {domain}…")
    subdomains: List[str] = []
    try:
        resp = http_client.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": api_key},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get("subdomains", []):
                subdomains.append(f"{sub}.{domain}")
        else:
            logger.warning(f"[SecurityTrails] HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logger.warning(f"[SecurityTrails] Error: {exc}")

    logger.info(f"[SecurityTrails] Found {len(subdomains)} subdomains.")
    return subdomains
