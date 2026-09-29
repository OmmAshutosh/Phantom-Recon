"""
PHANTOM RECON - Configuration & API Key Management
====================================================
Store your API keys here or use environment variables.
Never commit this file to version control with real keys.

Environment variable overrides (always takes precedence):
  SHODAN_API_KEY
  HUNTER_API_KEY
  VIRUSTOTAL_API_KEY
  NETLAS_API_KEY
  GIT_API_KEY
  CENSYS_API_ID + CENSYS_API_SECRET
"""

import os 


# Auto-load .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────────
#  API KEYS  (fill in or set as environment variables)
# ─────────────────────────────────────────────────────────────────

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
# Free key: https://account.shodan.io  (1 scan/month, basic results)
# Membership $49/mo: full search, export, history

HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
# Free: 25 requests/month  https://hunter.io/api-keys
# Used for: email harvesting, email pattern discovery

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
# Free: 500 requests/day  https://www.virustotal.com/gui/my-apikey
# Used for: subdomain enumeration, URL/IP reputation

NETLAS_API_KEY = os.getenv("NETLAS_API_KEY", "")
# Free: 50 requests/day  https://netlas.io/account
# Used for: DNS history, subdomain enumeration, IP history

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
# Free personal access token: https://github.com/settings/tokens
# Used for: code search, finding leaked secrets/emails

CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")
# Free: 250 queries/month  https://search.censys.io/account
# Used for: host discovery, certificate search (alternative to Shodan)

# ─────────────────────────────────────────────────────────────────
#  SCAN DEFAULTS
# ─────────────────────────────────────────────────────────────────

DEFAULT_THREADS = 15
DEFAULT_TIMEOUT = 5          # seconds per request
DEFAULT_DNS_TIMEOUT = 3      # seconds per DNS query
DEFAULT_PORT_TIMEOUT = 1.5   # seconds per port probe
DEFAULT_USER_AGENT = (
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
'AppleWebKit/537.36 (KHTML, like Gecko) '
'Chrome/124.0.0.0 Safari/537.36'
)
MAX_SUBDOMAINS_BRUTEFORCE = 500   # cap brute-force wordlist size

# ─────────────────────────────────────────────────────────────────
#  OUTPUT SETTINGS
# ─────────────────────────────────────────────────────────────────

OUTPUT_DIR = os.getenv(
    "PHANTOM_OUTPUT_DIR",
    os.path.join(os.getcwd(), "output")
)
# OUTPUT_DIR = os.getenv("PHANTOM_OUTPUT_DIR", "./output")
LOG_LEVEL = os.getenv("PHANTOM_LOG_LEVEL", "INFO")   # DEBUG | INFO | WARNING

# ─────────────────────────────────────────────────────────────────
#  USER-AGENT ROTATION (for web requests)
# ─────────────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
]

# ─────────────────────────────────────────────────────────────────
#  DNS RESOLVERS  (use multiple for reliability + evasion)
# ─────────────────────────────────────────────────────────────────

DNS_RESOLVERS = [
    "8.8.8.8",       # Google
    "8.8.4.4",       # Google secondary
    "1.1.1.1",       # Cloudflare
    "1.0.0.1",       # Cloudflare secondary
    "9.9.9.9",       # Quad9
    "208.67.222.222" # OpenDNS
]

# ─────────────────────────────────────────────────────────────────
#  RATE LIMITING  (be polite even on authorized targets)
# ─────────────────────────────────────────────────────────────────

REQUEST_DELAY = 0.1    # seconds between web requests
DNS_RATE_LIMIT = 0.05  # seconds between DNS queries

# ─────────────────────────────────────────────────────────────────
#  REPORT SETTINGS
# ─────────────────────────────────────────────────────────────────

REPORT_COMPANY_NAME = "PHANTOM RECON"
REPORT_AUTHOR = "Security Assessment Team"
REPORT_LOGO_PATH = None   # Optional: path to company logo PNG
REPORT_CLASSIFICATION = "CONFIDENTIAL"