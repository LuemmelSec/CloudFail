"""
CloudFail v2.0 — Certificate Transparency & host discovery

CT Sources (no API key required, tried in order):
  1. certspotter (sslmate)  — most reliable, 100 req/hour free
  2. crt.sh                 — fallback, sometimes slow/down
  3. BufferOver TLS         — fast, no auth, good coverage

Host discovery (API key required):
  4. Censys v2 REST API     — direct HTTP, avoids SDK routing bugs
  5. Shodan                 — SSL cert search
  6. SecurityTrails         — subdomain enumeration
"""
from __future__ import annotations

from typing import List, Optional, Set

import cloudfail.config as _cfg
from cloudfail.utils import logger, http_client


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_names(raw_names: list, domain: str) -> Set[str]:
    """Deduplicate and filter a flat list of DNS name strings."""
    found: Set[str] = set()
    for name in raw_names:
        name = str(name).strip().lstrip("*.")
        if name and domain.lower() in name.lower():
            found.add(name.lower())
    return found


# ---------------------------------------------------------------------------
# Source 1: certspotter  (primary — most reliable free CT source)
# ---------------------------------------------------------------------------

def _certspotter(domain: str) -> Set[str]:
    """
    Query certspotter (SSLMate) certificate transparency API.
    Free tier: 100 requests/hour, no API key needed.
    """
    found: Set[str] = set()
    try:
        resp = http_client.get(
            "https://api.certspotter.com/v1/issuances",
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            timeout=30,
        )
        if resp.status_code == 200:
            for cert in resp.json():
                for name in cert.get("dns_names", []):
                    name = name.strip().lstrip("*.")
                    if name and domain.lower() in name.lower():
                        found.add(name.lower())
            logger.info(f"[certspotter] Found {len(found)} names.")
        elif resp.status_code == 429:
            logger.warning("[certspotter] Rate limited (100 req/hour). Try again later.")
        else:
            logger.warning(f"[certspotter] HTTP {resp.status_code}.")
    except Exception as exc:
        logger.warning(f"[certspotter] Error: {exc}")
    return found


# ---------------------------------------------------------------------------
# Source 2: crt.sh  (secondary fallback)
# ---------------------------------------------------------------------------

def _crtsh(domain: str) -> Set[str]:
    """
    Query crt.sh certificate transparency log aggregator.
    Can be slow or return 5xx errors under load — used as fallback only.
    """
    found: Set[str] = set()

    def _parse(entries: list) -> None:
        for entry in entries:
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain.lower() in name.lower():
                    found.add(name.lower())

    # Try wildcard query first, then identity query
    for url in [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]:
        if found:
            break
        try:
            resp = http_client.get(url, timeout=45)
            if resp.status_code == 200:
                _parse(resp.json())
                if found:
                    logger.info(f"[crt.sh] Found {len(found)} names.")
            else:
                logger.warning(f"[crt.sh] HTTP {resp.status_code}.")
        except Exception as exc:
            logger.warning(f"[crt.sh] {exc}")
    return found


# ---------------------------------------------------------------------------
# Source 3: BufferOver TLS  (fast, no auth, good coverage)
# ---------------------------------------------------------------------------

def _bufferover(domain: str) -> Set[str]:
    """
    Query tls.bufferover.run for TLS certificate data.
    Free, no authentication required.
    """
    found: Set[str] = set()
    try:
        resp = http_client.get(
            f"https://tls.bufferover.run/dns",
            params={"q": f".{domain}"},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            # Response has 'Results' list of strings like "IP,,,DOMAIN,..."
            for entry in data.get("Results") or []:
                parts = str(entry).split(",")
                for part in parts:
                    part = part.strip().lstrip("*.")
                    if part and domain.lower() in part.lower() and " " not in part:
                        found.add(part.lower())
            logger.info(f"[BufferOver] Found {len(found)} names.")
        else:
            logger.warning(f"[BufferOver] HTTP {resp.status_code}.")
    except Exception as exc:
        logger.warning(f"[BufferOver] {exc}")
    return found


# ---------------------------------------------------------------------------
# Combined CT aggregation
# ---------------------------------------------------------------------------

def crtsh_subdomains(domain: str) -> List[str]:
    """
    Collect certificate transparency names from all available free sources.
    Sources are tried concurrently; results are merged and deduplicated.
    """
    import concurrent.futures

    logger.info(f"[CT] Querying certificate transparency sources for {domain}…")
    all_found: Set[str] = set()

    sources = {
        "certspotter": _certspotter,
        "crt.sh":      _crtsh,
        "bufferover":  _bufferover,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in sources.items()}
        for future in concurrent.futures.as_completed(futures):
            src_name = futures[future]
            try:
                result = future.result()
                all_found.update(result)
            except Exception as exc:
                logger.warning(f"[CT/{src_name}] Unexpected error: {exc}")

    logger.info(f"[CT] Total unique names across all sources: {len(all_found)}")
    return sorted(all_found)


# ---------------------------------------------------------------------------
# Censys v2  (direct REST API — avoids SDK routing/auth bugs)
# ---------------------------------------------------------------------------

def censys_hosts(
    domain: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
) -> List[str]:
    """
    Search Censys v2 REST API directly (no SDK) for hosts with TLS certs
    matching *domain*.

    Uses HTTP Basic Auth with api_id:api_secret as documented at:
    https://search.censys.io/api

    Free tier supports: hosts search, basic TLS queries.
    """
    if not (api_id and api_secret):
        return []

    logger.info(f"[Censys] Searching REST API for hosts matching {domain}…")
    ips: List[str] = []

    # Direct REST call — bypasses SDK entirely, no SSL patching needed
    # because our http_client already respects SSL_VERIFY
    try:
        import base64
        creds = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        auth_header = {"Authorization": f"Basic {creds}"}

        cursor: Optional[str] = None
        pages_fetched = 0
        max_pages = 5

        while pages_fetched < max_pages:
            params: dict = {
                "q": f'services.tls.certificates.leaf_data.names: "{domain}"',
                "per_page": 100,
                "fields": ["ip"],
            }
            if cursor:
                params["cursor"] = cursor

            resp = http_client.get(
                "https://search.censys.io/api/v2/hosts/search",
                params=params,
                headers=auth_header,
                timeout=20,
            )

            if resp.status_code == 401:
                logger.warning(
                    "[Censys] Authentication failed (401). "
                    "Ensure you are using Censys v2 API credentials from "
                    "https://search.censys.io/account/api — NOT the old app.censys.io keys."
                )
                break
            elif resp.status_code == 403:
                logger.warning(
                    "[Censys] Access denied (403). "
                    "Your account may not have access to this query. "
                    "Check your plan at https://search.censys.io/account."
                )
                break
            elif resp.status_code == 429:
                logger.warning("[Censys] Rate limited (429). Stopping pagination.")
                break
            elif resp.status_code != 200:
                logger.warning(f"[Censys] HTTP {resp.status_code}: {resp.text[:200]}")
                break

            data = resp.json()
            hits = data.get("result", {}).get("hits", [])
            for hit in hits:
                ip = hit.get("ip")
                if ip:
                    ips.append(ip)

            # Pagination
            next_cursor = (
                data.get("result", {})
                    .get("links", {})
                    .get("next")
            )
            if not next_cursor or not hits:
                break
            cursor = next_cursor
            pages_fetched += 1

    except Exception as exc:
        logger.warning(f"[Censys] Error: {exc}")

    logger.info(f"[Censys] Found {len(ips)} host IPs.")
    return ips


# ---------------------------------------------------------------------------
# Shodan  (optional)
# ---------------------------------------------------------------------------

def shodan_hosts(domain: str, api_key: Optional[str] = None) -> List[str]:
    """
    Use Shodan REST API to find IPs with *domain* in their SSL/TLS cert.
    Uses http_client directly (honours SSL_VERIFY automatically).
    """
    if not api_key:
        return []

    logger.info(f"[Shodan] Searching for hosts matching {domain}…")
    ips: List[str] = []
    try:
        resp = http_client.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key": api_key,
                "query": f"ssl.cert.subject.cn:{domain}",
                "facets": "",
            },
            timeout=20,
        )
        if resp.status_code == 200:
            for match in resp.json().get("matches", []):
                ip = match.get("ip_str")
                if ip:
                    ips.append(ip)
        elif resp.status_code == 401:
            logger.warning("[Shodan] Invalid API key.")
        else:
            logger.warning(f"[Shodan] HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logger.warning(f"[Shodan] Error: {exc}")

    logger.info(f"[Shodan] Found {len(ips)} host IPs.")
    return ips


# ---------------------------------------------------------------------------
# SecurityTrails  (optional)
# ---------------------------------------------------------------------------

def securitytrails_subdomains(
    domain: str,
    api_key: Optional[str] = None,
) -> List[str]:
    """
    Query SecurityTrails API for all known subdomains of *domain*.
    Uses http_client — SSL_VERIFY is honoured automatically.
    """
    if not api_key:
        return []

    logger.info(f"[SecurityTrails] Querying subdomains for {domain}…")
    subdomains: List[str] = []
    try:
        resp = http_client.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": api_key},
            timeout=20,
        )
        if resp.status_code == 200:
            for sub in resp.json().get("subdomains", []):
                subdomains.append(f"{sub}.{domain}")
        elif resp.status_code == 401:
            logger.warning("[SecurityTrails] Invalid API key.")
        else:
            logger.warning(
                f"[SecurityTrails] HTTP {resp.status_code}: {resp.text[:200]}"
            )
    except Exception as exc:
        logger.warning(f"[SecurityTrails] Error: {exc}")

    logger.info(f"[SecurityTrails] Found {len(subdomains)} subdomains.")
    return subdomains
