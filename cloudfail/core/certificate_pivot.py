"""
CloudFail v2.0 — Certificate Transparency log pivot (crt.sh + Censys + Shodan + ST)

SSL note: When --no-verify-ssl is active, config.SSL_VERIFY is False.
The Censys SDK creates its own requests.Session internally, so we apply
multiple layers of patching to ensure it also skips certificate verification.
"""
from __future__ import annotations

import os
from typing import List, Optional, Set

import cloudfail.config as _cfg
from cloudfail.utils import logger, http_client


# ---------------------------------------------------------------------------
# crt.sh  (primary passive source — no API key required)
# ---------------------------------------------------------------------------

def crtsh_subdomains(domain: str) -> List[str]:
    """
    Query crt.sh certificate transparency logs for all names matching *domain*.

    Uses a 60-second timeout (crt.sh is slow for large organisations).
    Falls back to an identity search if the wildcard query returns nothing.
    """
    logger.info(f"[crt.sh] Querying certificate transparency logs for {domain}…")
    found: Set[str] = set()

    def _parse_entries(entries: list) -> None:
        for entry in entries:
            name_value: str = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain.lower() in name.lower():
                    found.add(name.lower())

    # Primary: wildcard JSON query
    try:
        resp = http_client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=60,
        )
        if resp.status_code == 200:
            _parse_entries(resp.json())
        else:
            logger.warning(f"[crt.sh] HTTP {resp.status_code} from primary endpoint.")
    except Exception as exc:
        logger.warning(f"[crt.sh] Primary endpoint error: {exc}")

    # Fallback: identity search (catches certs issued directly to domain)
    if not found:
        logger.info("[crt.sh] Trying fallback identity search…")
        try:
            resp2 = http_client.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=60,
            )
            if resp2.status_code == 200:
                _parse_entries(resp2.json())
        except Exception as exc2:
            logger.warning(f"[crt.sh] Fallback error: {exc2}")

    logger.info(f"[crt.sh] Found {len(found)} unique names.")
    return sorted(found)


# ---------------------------------------------------------------------------
# Censys v2  (requires API key)
# ---------------------------------------------------------------------------

def _ensure_censys_no_verify() -> None:
    """
    Apply all available mechanisms to disable SSL verification inside the
    Censys SDK when the user has passed --no-verify-ssl.

    Approach (layered, most-to-least invasive):
      1. Set REQUESTS_CA_BUNDLE='' and CURL_CA_BUNDLE='' env vars — picked up
         by requests automatically.
      2. Suppress urllib3 InsecureRequestWarning.
      3. Monkey-patch CensysAPIBase.__init__ to set self._session.verify=False
         and self.verify=False after construction.
      4. After object construction the caller also sets h.verify=False and
         h._session.verify=False if those attributes exist.
    """
    if _cfg.SSL_VERIFY:
        return

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Env-var approach — works for any requests-based HTTP client
    os.environ["REQUESTS_CA_BUNDLE"] = ""
    os.environ["CURL_CA_BUNDLE"] = ""
    os.environ["SSL_CERT_FILE"] = ""

    # Monkey-patch approach — works even if env vars are ignored
    try:
        from censys.common import base as _cb  # type: ignore
        if hasattr(_cb, "CensysAPIBase") and not getattr(_cb, "_cf_patched", False):
            _orig = _cb.CensysAPIBase.__init__

            def _patched(self: object, *a: object, **kw: object) -> None:
                _orig(self, *a, **kw)
                # SDK v2.0–v2.1: stores session as self._session
                if hasattr(self, "_session"):
                    self._session.verify = False  # type: ignore[attr-defined]
                # SDK v2.2+: CensysHosts IS a requests.Session subclass
                if hasattr(self, "verify"):
                    self.verify = False  # type: ignore[attr-defined]

            _cb.CensysAPIBase.__init__ = _patched  # type: ignore[method-assign]
            _cb._cf_patched = True  # prevent double-patching
    except Exception:
        pass  # Best-effort


def censys_hosts(
    domain: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
) -> List[str]:
    """
    Search Censys v2 API for hosts with TLS certs matching *domain*.
    Fully honours --no-verify-ssl via layered SDK patching.
    """
    if not (api_id and api_secret):
        return []

    logger.info(f"[Censys] Searching for hosts matching {domain}…")
    ips: List[str] = []
    try:
        _ensure_censys_no_verify()

        from censys.search import CensysHosts  # type: ignore

        h = CensysHosts(api_id=api_id, api_secret=api_secret)

        # Belt-and-suspenders: set on the live object after construction
        if not _cfg.SSL_VERIFY:
            for attr in ("_session", "session"):
                if hasattr(h, attr):
                    getattr(h, attr).verify = False
            if hasattr(h, "verify"):
                h.verify = False  # type: ignore[attr-defined]

        query = f'services.tls.certificates.leaf_data.names: "{domain}"'
        for page in h.search(query, per_page=100, pages=3):
            for host in page:
                ip = host.get("ip")
                if ip:
                    ips.append(ip)

    except ImportError:
        logger.warning("[Censys] censys package not installed. Run: pip install censys")
    except Exception as exc:
        logger.warning(f"[Censys] Error: {exc}")

    logger.info(f"[Censys] Found {len(ips)} host IPs.")
    return ips


# ---------------------------------------------------------------------------
# Shodan  (optional)
# ---------------------------------------------------------------------------

def shodan_hosts(domain: str, api_key: Optional[str] = None) -> List[str]:
    """
    Use Shodan to find IPs with *domain* in their SSL/TLS certificate.
    """
    if not api_key:
        return []

    logger.info(f"[Shodan] Searching for hosts matching {domain}…")
    ips: List[str] = []
    try:
        import shodan  # type: ignore

        api = shodan.Shodan(api_key)
        # Shodan's client uses requests under the hood; patch verify if needed
        if not _cfg.SSL_VERIFY and hasattr(api, "session"):
            api.session.verify = False

        results = api.search(f"ssl.cert.subject.cn:{domain}")
        for match in results.get("matches", []):
            ip = match.get("ip_str")
            if ip:
                ips.append(ip)
    except ImportError:
        logger.warning("[Shodan] shodan package not installed. Run: pip install shodan")
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
    Uses the shared http_client, so SSL_VERIFY is honoured automatically.
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
        else:
            logger.warning(
                f"[SecurityTrails] HTTP {resp.status_code}: {resp.text[:200]}"
            )
    except Exception as exc:
        logger.warning(f"[SecurityTrails] Error: {exc}")

    logger.info(f"[SecurityTrails] Found {len(subdomains)} subdomains.")
    return subdomains
