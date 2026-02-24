"""
CloudFail v2.0 — Optional Tor routing handler

Requires:
  - Local Tor service running on 127.0.0.1:9050
  - PySocks package: pip install PySocks
"""
from __future__ import annotations

from cloudfail.utils import logger


def configure_tor(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """
    Configure the shared HTTP session to route through a Tor SOCKS5 proxy.
    Verifies connectivity by checking https://check.torproject.org/api/ip.
    Returns True on success, False on failure.
    """
    try:
        from cloudfail.utils.http_client import configure_tor as _configure_tor, get as http_get

        _configure_tor(host=host, port=port)
        logger.info(f"[Tor] Configured SOCKS5 proxy at {host}:{port} — verifying…")

        resp = http_get("https://check.torproject.org/api/ip", timeout=20)
        data = resp.json()
        tor_ip = data.get("IP", "unknown")
        is_tor = data.get("IsTor", False)

        if is_tor:
            logger.success(f"[Tor] Connection established. Exit node: [bold]{tor_ip}[/bold]")
        else:
            logger.warning(
                f"[Tor] Connected via proxy but Tor not confirmed. IP: {tor_ip}\n"
                "      Ensure the Tor service is running: sudo service tor start"
            )
        return True

    except Exception as exc:
        logger.error(f"[Tor] Configuration failed: {exc}")
        logger.warning("[Tor] Continuing without Tor. Use --no-tor to suppress this.")
        return False
