"""
CloudFail v2.0 — Cloudflare origin IP discovery tool
Author: modernized from m0rtem's original CloudFail (2018)
Version: 2.0 (2026)
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Set

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cloudfail import config
from cloudfail.utils import logger
from cloudfail.core import (
    cloudflare,
    certificate_pivot,
    dns_history,
    dnsdumpster,
    asn_filter,
    tor_handler,
)

console = Console()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudfail",
        description="CloudFail v2.0 — Cloudflare origin IP discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m cloudfail -t example.com --confirm-scope\n"
            "  python -m cloudfail -t example.com --confirm-scope --no-verify-ssl\n"
            "  python -m cloudfail -t example.com --censys-api-id ID --censys-api-secret SECRET --confirm-scope --no-verify-ssl\n"
            "  python -m cloudfail -t example.com --passive-only --output json --output-file out.json --confirm-scope\n"
            "\n"
            "NOTE: Put ALL arguments on ONE line. Do not use shell backslash continuation.\n"
        ),
    )

    # Core
    p.add_argument("-t", "--target", required=True,
                   help="Target domain (e.g. example.com)")
    p.add_argument("--confirm-scope", action="store_true", required=True,
                   help="[REQUIRED] Confirm you have authorisation to test this target")

    # API keys
    p.add_argument("--censys-api-id",      metavar="ID",     help="Censys v2 API ID (from search.censys.io/account/api)")
    p.add_argument("--censys-api-secret",  metavar="SECRET", help="Censys v2 API secret")
    p.add_argument("--securitytrails-api", metavar="KEY",    help="SecurityTrails API key")
    p.add_argument("--shodan-api",         metavar="KEY",    help="Shodan API key")

    # Modes
    p.add_argument("--passive-only", action="store_true",
                   help="Only perform passive recon — skip subdomain bruteforce")
    p.add_argument("--tor", action="store_true",
                   help="Route traffic through local Tor SOCKS5 proxy (127.0.0.1:9050)")
    p.add_argument("--no-tor", action="store_true",
                   help="Explicitly disable Tor (already off by default)")
    p.add_argument("--no-verify-ssl", action="store_true",
                   help="Disable SSL certificate verification (use behind corporate TLS-inspection proxies)")
    p.add_argument("--subdomains", metavar="FILE",
                   help="Custom wordlist for subdomain bruteforce (default: built-in 11k list)")
    p.add_argument("--threads", type=int, default=config.DEFAULT_THREADS, metavar="N",
                   help=f"Threads for DNS resolution (default: {config.DEFAULT_THREADS})")
    p.add_argument("--update-ranges", "--update-range", dest="update_ranges",
                   action="store_true",
                   help="Re-download Cloudflare IP ranges before scanning")

    # Output
    p.add_argument("--output", choices=["text", "json"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--output-file", metavar="PATH",
                   help="Also write results to this file")

    return p


# ---------------------------------------------------------------------------
# Scan result container
# ---------------------------------------------------------------------------

class ScanResult:
    def __init__(self, target: str) -> None:
        self.target = target
        self.resolved_ip: Optional[str] = None
        self.is_cloudflare: Optional[bool] = None
        self.crtsh_names: List[str] = []
        self.dnsdumpster_records: List[Dict[str, str]] = []
        self.censys_ips: List[str] = []
        self.shodan_ips: List[str] = []
        self.st_subdomains: List[str] = []
        self.passive_dns_ips: List[str] = []
        self.subdomain_hits: List[Dict[str, Any]] = []
        self.all_candidate_ips: Set[str] = set()
        self.non_cf_ips: List[Dict[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target":                    self.target,
            "resolved_ip":               self.resolved_ip,
            "behind_cloudflare":         self.is_cloudflare,
            "crt_sh_names":              self.crtsh_names,
            "dnsdumpster_records":       self.dnsdumpster_records,
            "censys_ips":                self.censys_ips,
            "shodan_ips":                self.shodan_ips,
            "securitytrails_subdomains": self.st_subdomains,
            "passive_dns_ips":           self.passive_dns_ips,
            "subdomain_hits":            self.subdomain_hits,
            "non_cloudflare_ips":        self.non_cf_ips,
        }


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

def phase_init(target: str, cf_ranges: List[str]) -> ScanResult:
    result = ScanResult(target)
    logger.section("Phase 1: Target Initialisation")

    ip = cloudflare.resolve_domain(target)
    if ip is None:
        logger.error(f"Cannot resolve '{target}'. Check the domain name and try again.")
        sys.exit(1)

    result.resolved_ip = ip
    logger.info(f"Resolved [bold]{target}[/bold] → [bold cyan]{ip}[/bold cyan]")

    in_cf = cloudflare.is_cloudflare_ip(ip, cf_ranges)
    result.is_cloudflare = in_cf

    if in_cf:
        logger.success(f"{target} is [bold]behind Cloudflare[/bold]. Proceeding with origin discovery…")
    else:
        logger.warning(f"{target} does NOT appear to be behind Cloudflare (IP: {ip}).")
        logger.warning("Continuing anyway — the tool may still find useful intelligence.")

    return result


def phase_passive(
    result: ScanResult,
    censys_id: Optional[str],
    censys_secret: Optional[str],
    shodan_key: Optional[str],
    st_key: Optional[str],
    cf_ranges: List[str],
) -> None:
    logger.section("Phase 2: Passive Certificate & DNS Recon")

    # ── Certificate Transparency (certspotter + crt.sh + bufferover) ─────
    names = certificate_pivot.crtsh_subdomains(result.target)
    result.crtsh_names = names

    # ── DNSDumpster (CSRF-aware scraper) ──────────────────────────────────
    dd_records = dnsdumpster.query(result.target)
    result.dnsdumpster_records = dd_records
    for rec in dd_records:
        ip = rec.get("ip", "")
        if ip and not cloudflare.is_cloudflare_ip(ip, cf_ranges):
            result.all_candidate_ips.add(ip)
            logger.success(
                f"[DNSDumpster/{rec.get('type','HOST')}] "
                f"{rec.get('hostname','')} → {ip}  {rec.get('provider','')}"
            )

    # ── Censys v2 ─────────────────────────────────────────────────────────
    if censys_id and censys_secret:
        cips = certificate_pivot.censys_hosts(result.target, censys_id, censys_secret)
        result.censys_ips = cips
        result.all_candidate_ips.update(cips)

    # ── Shodan ────────────────────────────────────────────────────────────
    if shodan_key:
        sips = certificate_pivot.shodan_hosts(result.target, shodan_key)
        result.shodan_ips = sips
        result.all_candidate_ips.update(sips)

    # ── SecurityTrails ────────────────────────────────────────────────────
    if st_key:
        st_subs = certificate_pivot.securitytrails_subdomains(result.target, st_key)
        result.st_subdomains = st_subs

    # ── Multi-source passive DNS ──────────────────────────────────────────
    logger.info("[PassiveDNS] Querying HackerTarget + AlienVault OTX + ViewDNS…")
    pdns = dns_history.passive_dns_lookup(result.target)
    result.passive_dns_ips = pdns
    result.all_candidate_ips.update(pdns)

    logger.info(
        f"Passive phase complete: "
        f"{len(result.crtsh_names)} CT names, "
        f"{len(result.dnsdumpster_records)} DNSDumpster records, "
        f"{len(result.all_candidate_ips)} candidate IPs."
    )


def phase_subdomain(
    result: ScanResult,
    wordlist_path: Optional[str],
    threads: int,
    cf_ranges: List[str],
) -> None:
    logger.section("Phase 3: Subdomain Resolution")

    hostnames: List[str] = list(result.crtsh_names) + list(result.st_subdomains)

    # Add DNSDumpster hostnames
    for rec in result.dnsdumpster_records:
        h = rec.get("hostname", "").strip()
        if h and result.target in h:
            hostnames.append(h)

    wl_path = wordlist_path or str(config.SUBDOMAINS_FILE)
    try:
        with open(wl_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                sub = line.strip().lstrip("*.")
                if sub:
                    hostnames.append(f"{sub}.{result.target}")
    except FileNotFoundError:
        logger.warning(f"Wordlist not found: {wl_path}. Using CT + DNSDumpster names only.")

    hostnames = list(set(hostnames))
    logger.info(f"Resolving {len(hostnames)} hostnames with {threads} threads…")

    if dns_history.check_wildcard(result.target):
        logger.warning(
            "Wildcard DNS detected — bruteforce results unreliable. "
            "CT + DNSDumpster + passive names are still valid."
        )

    resolved = dns_history.resolve_bulk(hostnames, max_workers=threads)

    hits: List[Dict[str, Any]] = []
    for host, ip in resolved.items():
        if ip is None:
            continue
        in_cf = cloudflare.is_cloudflare_ip(ip, cf_ranges)
        result.all_candidate_ips.add(ip)
        hits.append({"host": host, "ip": ip, "behind_cloudflare": in_cf})

    hits.sort(key=lambda h: h["behind_cloudflare"])  # non-CF first
    result.subdomain_hits = hits
    non_cf = sum(1 for h in hits if not h["behind_cloudflare"])
    logger.info(
        f"Resolved {len(hits)} hostnames — "
        f"[bold green]{non_cf} not behind Cloudflare[/bold green]."
    )


def phase_filter(result: ScanResult, cf_ranges: List[str]) -> None:
    logger.section("Phase 4: Candidate IP Enrichment & Filtering")

    if not result.all_candidate_ips:
        logger.warning("No candidate IPs to evaluate.")
        return

    logger.info(
        f"Enriching {len(result.all_candidate_ips)} unique candidate IPs…"
    )
    enriched = asn_filter.enrich_ips(list(result.all_candidate_ips), cf_ranges=cf_ranges)
    result.non_cf_ips = [e for e in enriched if e["is_cloudflare"] != "yes"]

    if result.non_cf_ips:
        logger.success(f"[bold]{len(result.non_cf_ips)} non-Cloudflare IP(s)[/bold] discovered!")
    else:
        logger.warning("No non-Cloudflare IPs discovered in this scan.")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def render_results(
    result: ScanResult,
    output_format: str,
    output_file: Optional[str],
) -> None:
    if output_format == "json":
        out = json.dumps(result.to_dict(), indent=2)
        console.print(out)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(out)
            logger.info(f"JSON results saved to {output_file}")
        return

    console.print()
    summary_lines = [
        f"[bold]Target:[/bold]                 {result.target}",
        f"[bold]Resolved IP:[/bold]            {result.resolved_ip or 'N/A'}",
        f"[bold]Behind Cloudflare:[/bold]      {'[green]Yes[/green]' if result.is_cloudflare else '[yellow]No / Unknown[/yellow]'}",
        f"[bold]CT Names (multi-source):[/bold] {len(result.crtsh_names)}",
        f"[bold]DNSDumpster Records:[/bold]    {len(result.dnsdumpster_records)}",
        f"[bold]Subdomain Hits:[/bold]         {len(result.subdomain_hits)}",
        f"[bold]Candidate IPs:[/bold]          {len(result.all_candidate_ips)}",
        f"[bold]Non-CF IPs Found:[/bold]       [{'green' if result.non_cf_ips else 'yellow'}]{len(result.non_cf_ips)}[/{'green' if result.non_cf_ips else 'yellow'}]",
    ]
    console.print(Panel(
        "\n".join(summary_lines),
        title="[bold blue]CloudFail v2.0 — Scan Summary[/bold blue]",
    ))

    # DNSDumpster records table
    if result.dnsdumpster_records:
        console.print()
        dd_tbl = Table(
            title="[bold yellow]DNSDumpster Records[/bold yellow]",
            show_header=True,
            header_style="bold yellow",
        )
        dd_tbl.add_column("Type",     style="dim",       width=6)
        dd_tbl.add_column("Hostname", style="cyan")
        dd_tbl.add_column("IP",       style="bold white", no_wrap=True)
        dd_tbl.add_column("Provider", style="dim")

        for rec in result.dnsdumpster_records:
            from cloudfail.core.cloudflare import is_cloudflare_ip
            ip = rec.get("ip", "")
            ip_style = "[red]" if is_cloudflare_ip(ip) else "[green]"
            dd_tbl.add_row(
                rec.get("type", ""),
                rec.get("hostname", ""),
                f"{ip_style}{ip}[/]",
                rec.get("provider", ""),
            )
        console.print(dd_tbl)

    # Non-CF IPs table
    if result.non_cf_ips:
        console.print()
        tbl = Table(
            title="[bold green]⚠  Non-Cloudflare IPs — Potential Origin Servers[/bold green]",
            show_header=True,
            header_style="bold magenta",
        )
        tbl.add_column("IP Address", style="bold cyan", no_wrap=True)
        tbl.add_column("ASN",        style="yellow")
        tbl.add_column("CF Status",  justify="center")
        tbl.add_column("Confidence", justify="right")
        for row in result.non_cf_ips:
            cf_label = {
                "no":      "[green]✘ Not CF[/green]",
                "likely":  "[yellow]~ Possibly CF[/yellow]",
                "unknown": "[dim]? Unknown[/dim]",
            }.get(row["is_cloudflare"], row["is_cloudflare"])
            tbl.add_row(row["ip"], row["asn"], cf_label, f"{row['confidence']}%")
        console.print(tbl)

    # Subdomain hits (capped)
    if result.subdomain_hits:
        console.print()
        cap   = config.MAX_SUBDOMAIN_DISPLAY
        shown = result.subdomain_hits[:cap]
        total = len(result.subdomain_hits)
        sub_tbl = Table(
            title=f"[bold]Resolved Subdomains[/bold] (showing {len(shown)} of {total})",
            show_header=True,
            header_style="bold blue",
        )
        sub_tbl.add_column("Hostname", style="cyan")
        sub_tbl.add_column("IP",       style="white")
        sub_tbl.add_column("CF?",      justify="center")
        for hit in shown:
            cf_label = "[red]✔ CF[/red]" if hit["behind_cloudflare"] else "[green]✘ Origin?[/green]"
            sub_tbl.add_row(hit["host"], hit["ip"], cf_label)
        console.print(sub_tbl)
        if total > cap:
            logger.info(f"{total - cap} more hits — use --output json --output-file out.json to see all.")

    # File output
    if output_file:
        lines = [
            f"CloudFail v2.0 — Results for {result.target}",
            "=" * 60,
            f"Resolved IP  : {result.resolved_ip}",
            f"Behind CF    : {result.is_cloudflare}",
            "",
            "# DNSDumpster Records",
        ]
        for rec in result.dnsdumpster_records:
            lines.append(
                f"  [{rec.get('type','')}] {rec.get('hostname',''):50s} {rec.get('ip',''):18s} {rec.get('provider','')}"
            )
        lines += ["", "# Non-Cloudflare IPs"]
        for row in result.non_cf_ips:
            lines.append(
                f"  [NON-CF] {row['ip']:20s}  ASN: {row['asn']:12s}  Confidence: {row['confidence']}%"
            )
        lines += ["", "# Subdomain Hits"]
        for hit in result.subdomain_hits:
            tag = "CF" if hit["behind_cloudflare"] else "ORIGIN?"
            lines.append(f"  [{tag:7s}] {hit['host']:50s}  {hit['ip']}")
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        logger.info(f"Full results saved to {output_file}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    console.print(f"[bold red]{config.BANNER}[/bold red]")
    console.print(config.DISCLAIMER)

    # 1. SSL — must be set before any HTTP call
    if args.no_verify_ssl:
        from cloudfail.utils.http_client import set_ssl_verify
        set_ssl_verify(False)
        logger.warning(
            "[bold yellow]SSL verification DISABLED.[/bold yellow] "
            "Required for corporate TLS-inspection proxies."
        )

    # 2. Tor
    if args.tor and not args.no_tor:
        tor_handler.configure_tor()

    # 3. CF ranges
    if args.update_ranges:
        cloudflare.update_cf_ranges()
    cf_ranges = cloudflare.load_cf_ranges()
    if not cf_ranges:
        logger.error(
            "Could not load Cloudflare IP ranges.\n"
            "  • Behind a proxy?  Add --no-verify-ssl\n"
            "  • Try: --update-ranges --no-verify-ssl"
        )
        sys.exit(1)
    logger.info(f"Loaded {len(cf_ranges)} Cloudflare CIDR blocks.")

    # 4. Phases
    result = phase_init(args.target, cf_ranges)

    phase_passive(
        result,
        censys_id=args.censys_api_id,
        censys_secret=args.censys_api_secret,
        shodan_key=args.shodan_api,
        st_key=args.securitytrails_api,
        cf_ranges=cf_ranges,
    )

    if args.passive_only:
        logger.info("--passive-only: skipping subdomain bruteforce.")
    else:
        phase_subdomain(result, args.subdomains, args.threads, cf_ranges)

    phase_filter(result, cf_ranges)
    render_results(result, args.output, args.output_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted by user.[/bold yellow]")
        sys.exit(0)
