"""
CloudFail v2.0 — Optional Tor routing handler
"""
from __future__ import annotations

from cloudfail.utils import logger


def configure_tor(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """
    Attempt to route HTTP requests through a local Tor SOCKS5 proxy.
    Returns True on success, False on failure.
    """
    try:
        from cloudfail.utils.http_client import configure_tor as _configure_tor, get as http_get

        _configure_tor(host=host, port=port)

        # Verify connectivity
        resp = http_get("https://check.torproject.org/api/ip", timeout=15)
        data = resp.json()
        tor_ip = data.get("IP", "unknown")
        is_tor = data.get("IsTor", False)

        if is_tor:
            logger.success(f"Tor connection established. Exit node IP: [bold]{tor_ip}[/bold]")
        else:
            logger.warning(f"Connected via proxy but Tor not confirmed. IP: {tor_ip}")
        return True

    except Exception as exc:
        logger.error(f"Tor configuration failed: {exc}")
        logger.warning("Continuing without Tor. Use --no-tor to suppress this warning.")
        return False
