"""
CloudFail v2.0 — Centralised HTTP client

All HTTP calls in this project must use this module.
Provides:
  - requests.Session with retry / exponential backoff
  - Configurable SSL verification
  - Optional Tor SOCKS5 proxy routing
  - Global rate-limit delay
  - Modern User-Agent header
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

_DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0"
)

_DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": _DEFAULT_UA,
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
}


def _build_session(
    proxies: Optional[Dict[str, str]] = None,
    verify: bool = True,
) -> requests.Session:
    session = requests.Session()

    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(_DEFAULT_HEADERS)
    session.verify = verify

    if proxies:
        session.proxies.update(proxies)

    return session


# Module-level shared session — rebuilt by set_ssl_verify / configure_tor
_session: requests.Session = _build_session()


def set_ssl_verify(verify: bool) -> None:
    """
    Globally toggle SSL certificate verification.
    Call this once before any requests are made.
    Set verify=False when behind a corporate TLS-inspection proxy.
    """
    global _session
    _cfg.SSL_VERIFY = verify
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _session = _build_session(
        proxies=dict(_session.proxies) if _session.proxies else None,
        verify=verify,
    )


def configure_tor(host: str = "127.0.0.1", port: int = 9050) -> None:
    """Re-configure the shared session to route through a SOCKS5 proxy (Tor)."""
    global _session
    proxies = {
        "http": f"socks5h://{host}:{port}",
        "https": f"socks5h://{host}:{port}",
    }
    _session = _build_session(proxies=proxies, verify=_cfg.SSL_VERIFY)


def get(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = HTTP_TIMEOUT,
    allow_redirects: bool = True,
) -> requests.Response:
    """
    Perform a GET request.
    Applies global rate-limit delay, merged headers, SSL_VERIFY, and retry adapter.
    """
    time.sleep(RATE_LIMIT_DELAY)

    from cloudfail.utils.logger import debug
    debug(f"GET {url}  params={params}")

    merged: Dict[str, str] = dict(_DEFAULT_HEADERS)
    if headers:
        merged.update(headers)

    return _session.get(
        url,
        params=params,
        headers=merged,
        timeout=timeout,
        verify=_cfg.SSL_VERIFY,
        allow_redirects=allow_redirects,
    )


def post(
    url: str,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Any] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = HTTP_TIMEOUT,
) -> requests.Response:
    """Perform a POST request via the shared session."""
    time.sleep(RATE_LIMIT_DELAY)

    from cloudfail.utils.logger import debug
    debug(f"POST {url}")

    merged: Dict[str, str] = dict(_DEFAULT_HEADERS)
    if headers:
        merged.update(headers)

    return _session.post(
        url,
        data=data,
        json=json,
        headers=merged,
        timeout=timeout,
        verify=_cfg.SSL_VERIFY,
    )
