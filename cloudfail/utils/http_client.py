"""
CloudFail v2.0 — Centralised HTTP client with retry, rate limiting, SSL control
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import cloudfail.config as _cfg
from cloudfail.config import HTTP_TIMEOUT, RATE_LIMIT_DELAY

_DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
        "Gecko/20100101 Firefox/120.0"
    )
}


def _build_session(proxies: Optional[Dict[str, str]] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(_DEFAULT_HEADERS)
    if proxies:
        session.proxies.update(proxies)
    return session


# Module-level shared session
_session: requests.Session = _build_session()


def set_ssl_verify(verify: bool) -> None:
    """
    Globally toggle SSL certificate verification.
    Call this before any HTTP requests are made.
    Pass verify=False when behind a corporate TLS-inspection proxy.
    """
    global _session
    _cfg.SSL_VERIFY = verify
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # Rebuild session to pick up the new setting
    _session = _build_session(dict(_session.proxies) if _session.proxies else None)


def configure_tor(host: str = "127.0.0.1", port: int = 9050) -> None:
    """Re-configure the shared session to route through a SOCKS5 proxy (Tor)."""
    global _session
    proxies = {
        "http":  f"socks5h://{host}:{port}",
        "https": f"socks5h://{host}:{port}",
    }
    _session = _build_session(proxies=proxies)


def get(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = HTTP_TIMEOUT,
) -> requests.Response:
    """Perform a GET request with rate limiting and global SSL_VERIFY setting."""
    time.sleep(RATE_LIMIT_DELAY)
    merged = dict(_DEFAULT_HEADERS)
    if headers:
        merged.update(headers)
    return _session.get(
        url,
        params=params,
        headers=merged,
        timeout=timeout,
        verify=_cfg.SSL_VERIFY,
    )
