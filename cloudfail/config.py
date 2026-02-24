"""
CloudFail v2.0 — Configuration & defaults
"""
from pathlib import Path
from typing import List

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

CF_SUBNET_CACHE  = DATA_DIR / "cf-subnet.txt"
SUBDOMAINS_FILE  = DATA_DIR / "subdomains.txt"

CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
CF_IPS_V6_URL = "https://www.cloudflare.com/ips-v6"

CLOUDFLARE_ASN = "AS13335"

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"

DEFAULT_THREADS  = 10
HTTP_TIMEOUT     = 10
RATE_LIMIT_DELAY = 0.3

# SSL verification — toggled at runtime by --no-verify-ssl flag
SSL_VERIFY: bool = True

# Hardcoded Cloudflare IP ranges — used as fallback when live download fails
# Source: https://www.cloudflare.com/ips-v4  +  /ips-v6  (updated Jan 2025)
CLOUDFLARE_RANGES_FALLBACK: List[str] = [
    # IPv4
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    # IPv6
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

BANNER = r"""
 _______ _                 _ _______     _ _          ______    _____  
(_______) |               | (_______)   (_) |        (_____ \  (_____) 
 _      | | ___  _   _  __| |_____ _____ _| |    _   _ ____) ) _  __ _ 
| |     | |/ _ \| | | |/ _  |  ___|____ | | |   | | | / ____/ | |/ /| |
| |_____| | |_| | |_| ( (_| | |   / ___ | | |    \ V / (_____ |   /_| |
 \______)\_)___/|____/ \____|_|   \_____|_|\_)    \_/|_______|_)_____/ 
                                                                       
                                      v2.0 | 2026 Edition | Enhanced by FR13ND0x7f
"""

DISCLAIMER = (
    "\n[bold red]LEGAL DISCLAIMER[/bold red]: This tool is for authorized "
    "testing and research purposes only.\nUnauthorized use against systems "
    "you do not own or have explicit permission to test is illegal.\n"
)
