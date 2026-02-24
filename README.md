# CloudFail v2.0

> **Cloudflare Origin IP Discovery Tool** — modernized for 2026  
> Originally created by [m0rtem](https://github.com/m0rtem/CloudFail) (2018)  
> Rewritten & extended by the security research community

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized penetration testing and security research purposes only.**  
> Unauthorized use against systems you do not own or have explicit written permission to test is illegal.  
> The authors accept no liability for misuse.

---

## What is CloudFail?

CloudFail v2.0 discovers the **origin IP address** of websites hidden behind Cloudflare by aggregating:

- **Certificate Transparency logs** (crt.sh) — passive, no API key required
- **Censys v2** — deep TLS certificate pivoting (API key required)
- **Shodan** — banner/certificate scanning (API key required)
- **SecurityTrails** — historical subdomain enumeration (API key required)
- **Passive DNS** — HackerTarget free historical lookup
- **Subdomain bruteforce** — resolves 11,000+ subdomains to find non-CF IPs

Unlike the original CloudFail, v2.0:
- Fixes all broken integrations (DNSDumpster, Crimeflare)
- Uses live Cloudflare IP ranges (not a static file)
- Performs ASN validation as a fallback
- Produces structured JSON output
- Uses async thread pools for fast resolution
- Works cleanly on Python 3.10–3.12

---

## Installation

```bash
# Clone or unzip the project
cd cloudfail

# Install dependencies (Python 3.10–3.12 recommended)
pip install -r requirements.txt

# Optional: install Shodan and Censys SDK
pip install censys shodan
```

---

## Usage

### Minimal (passive + subdomain bruteforce)
```bash
python -m cloudfail -t example.com --confirm-scope
```

### Passive only (no DNS bruteforce)
```bash
python -m cloudfail -t example.com --passive-only --confirm-scope
```

### With Censys (recommended)
```bash
python -m cloudfail \
  -t example.com \
  --censys-api-id YOUR_ID \
  --censys-api-secret YOUR_SECRET \
  --confirm-scope
```

### Full scan with all APIs
```bash
python -m cloudfail \
  -t example.com \
  --censys-api-id YOUR_ID \
  --censys-api-secret YOUR_SECRET \
  --shodan-api YOUR_SHODAN_KEY \
  --securitytrails-api YOUR_ST_KEY \
  --threads 20 \
  --confirm-scope
```

### JSON output
```bash
python -m cloudfail \
  -t example.com \
  --output json \
  --output-file results.json \
  --confirm-scope
```

### Via Tor
```bash
# Requires Tor running locally on port 9050
python -m cloudfail -t example.com --tor --confirm-scope
```

---

## Arguments

| Flag | Description |
|------|-------------|
| `-t, --target` | Target domain (required) |
| `--confirm-scope` | **Required** — confirms authorization to test |
| `--censys-api-id` | Censys v2 API ID |
| `--censys-api-secret` | Censys v2 API Secret |
| `--shodan-api` | Shodan API key |
| `--securitytrails-api` | SecurityTrails API key |
| `--passive-only` | Skip subdomain bruteforce |
| `--tor` | Route through local Tor (SOCKS5 127.0.0.1:9050) |
| `--no-tor` | Explicitly disable Tor |
| `--threads N` | Thread count for DNS resolution (default: 10) |
| `--subdomains FILE` | Custom subdomain wordlist |
| `--update-ranges` | Re-download Cloudflare IP ranges |
| `--output text/json` | Output format |
| `--output-file PATH` | Save results to file |

---

## Scan Phases

```
Phase 1: Target Initialisation
  └── Resolve domain → check if IP is in Cloudflare ranges

Phase 2: Passive Certificate & DNS Recon
  ├── crt.sh  (certificate transparency)
  ├── Censys v2  (TLS certificate pivoting)
  ├── Shodan  (optional)
  ├── SecurityTrails  (optional)
  └── HackerTarget PassiveDNS

Phase 3: Subdomain Resolution
  ├── Merge crt.sh names + SecurityTrails + wordlist
  ├── Wildcard DNS detection
  └── Thread-pool DNS resolution (max 10 workers)

Phase 4: Candidate IP Enrichment
  ├── ASN lookup per IP (HackerTarget)
  ├── Cloudflare range membership check
  └── Confidence scoring
```

---

## Output Example

```
╭─────────────────────────────────────────────────────╮
│           CloudFail v2.0 — Scan Summary             │
│ Target:            example.com                      │
│ Resolved IP:       104.21.x.x                       │
│ Behind Cloudflare: Yes                              │
│ CT Names (crt.sh): 47                               │
│ Subdomain Hits:    312                              │
│ Candidate IPs:     18                               │
│ Non-CF IPs Found:  3                                │
╰─────────────────────────────────────────────────────╯

Non-Cloudflare IPs (Potential Origin Servers)
┌──────────────────┬──────────┬───────────┬────────────┐
│ IP Address       │ ASN      │ CF Status │ Confidence │
├──────────────────┼──────────┼───────────┼────────────┤
│ 45.33.x.x        │ AS63949  │ ✘ Not CF  │ 90%        │
│ 198.51.x.x       │ AS16509  │ ✘ Not CF  │ 90%        │
└──────────────────┴──────────┴───────────┴────────────┘
```

---

## Project Structure

```
cloudfail/
├── __main__.py          # CLI entrypoint + orchestration
├── __init__.py
├── config.py            # Constants and paths
├── core/
│   ├── cloudflare.py    # CF IP ranges + detection
│   ├── certificate_pivot.py  # crt.sh, Censys, Shodan, SecurityTrails
│   ├── dns_history.py   # DNS resolution + passive DNS
│   ├── asn_filter.py    # ASN lookup + enrichment
│   └── tor_handler.py   # Optional Tor routing
├── utils/
│   ├── logger.py        # Rich-based logging
│   └── http_client.py   # Session management + retry
└── data/
    └── subdomains.txt   # 11,000+ subdomain wordlist
requirements.txt
README.md
```

---

## API Keys

| Service | Free Tier | URL |
|---------|-----------|-----|
| Censys v2 | 250 queries/month | https://search.censys.io/account |
| Shodan | $49/month | https://account.shodan.io |
| SecurityTrails | 50 queries/month | https://securitytrails.com/app/account |
| HackerTarget | Free (limited) | Built-in, no key needed |
| crt.sh | Free, unlimited | Built-in, no key needed |

---

## Changelog from v1.0.5

- Removed broken DNSDumpster scraping
- Removed outdated Crimeflare database
- Removed `win_inet_pton` Windows-only dependency
- Removed `colorama` (replaced with `rich`)
- Removed `socks` / `sockshandler` (replaced with `requests[socks]`)
- Added Censys v2 API integration
- Added crt.sh certificate transparency pivot
- Added Shodan integration
- Added SecurityTrails integration
- Added ASN-based Cloudflare validation
- Added thread-safe DNS resolution
- Added JSON output mode
- Added rate limiting
- Added `--confirm-scope` ethical guardrail
- Full Python 3.10–3.12 compatibility
- Zero deprecated library usage
- Zero invalid escape sequence warnings
- Modular, typed, documented codebase

---

## License

MIT License — see original CloudFail for attribution.
