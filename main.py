"""
Standalone Elite 12 Phishing Engine
===================================
A fully functional, self-contained Python backend.
Combines strict data structures with live API requests for the 12 core parameters.
No external local file imports required.
"""

import os
import sys
import json
import time
import base64
import argparse
import ipaddress
import requests
import urllib3
import mmh3
import Levenshtein
import urllib.parse
from typing import Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress insecure request warnings (favicon fetch over http)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

# ─── API KEYS ─────────────────────────────────────────────────────────────────
VT_API_KEY    = os.getenv("VT_API_KEY")
OTX_API_KEY   = os.getenv("OTX_API_KEY")
IPINFO_TOKEN  = os.getenv("IPINFO_TOKEN")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
PROTECTED_BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook", "chase", "wellsfargo"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly"]
BOGON_NETWORKS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"
]

# VT free tier: 4 req/min → ~16s between full domain scans (VT + OTX + crt.sh + favicon)
VT_RATE_LIMIT_SLEEP = 16


# ─── SESSION WITH RETRY ───────────────────────────────────────────────────────
def build_session() -> requests.Session:
    """Returns a session with automatic retry/backoff on transient failures."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.5,          # waits 1.5s, 3s, 6s between retries
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

SESSION = build_session()


# ─── DATA STRUCTURE ───────────────────────────────────────────────────────────
@dataclass
class PhishingFeatures:
    indicator: str
    indicator_type: str

    # 1. Deception & Brand  (None = not applicable for IPs)
    corporate_lookalike_distance: Optional[float] = None
    brand_homoglyph_detected: Optional[bool]      = None
    url_shortener_used: Optional[bool]             = None

    # 2. Time-Based Volatility
    passive_dns_first_seen: Optional[str]            = None   # FIX: was always ""
    domain_expiration_duration_days: Optional[int]   = None
    certificate_transparency_velocity: Optional[int] = None

    # 3. Identity & Visuals  (None = not applicable for IPs)
    favicon_hash: Optional[str] = None

    # 4. Consensus & Reputation
    threat_feed_source_count: int        = 0
    confidence_score_stix: int           = 0
    open_threat_exchange_pulse_count: int = 0

    # 5. Infrastructure Risk
    ip_hosting_type: str             = "UNKNOWN"
    hosting_provider_abuse_history: int = 0
    is_bogon_space: bool             = False


# ─── UTILITY FUNCTIONS ────────────────────────────────────────────────────────
def is_ip_address(indicator: str) -> bool:
    try:
        ipaddress.ip_address(indicator)
        return True
    except ValueError:
        return False

def sanitize_indicator(indicator: str) -> str:
    """Strips http://, https://, and paths to extract the raw domain/IP."""
    indicator = indicator.strip()
    if indicator.startswith("http://") or indicator.startswith("https://"):
        parsed = urllib.parse.urlparse(indicator)
        indicator = parsed.netloc
    indicator = indicator.split('/')[0]
    return indicator

def is_bogon(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(net, strict=False) for net in BOGON_NETWORKS)
    except ValueError:
        return False

def classify_hosting(org_name: str) -> str:
    org_lower = str(org_name).lower()
    if any(kw in org_lower for kw in ["amazon", "aws", "google", "azure", "cloudflare", "digitalocean", "linode", "hetzner", "ovh"]):
        return "CLOUD"
    if any(kw in org_lower for kw in ["koddos", "frantech", "alexhost", "combahton"]):
        return "BULLETPROOF"
    if any(kw in org_lower for kw in ["comcast", "verizon", "att", "xfinity", "spectrum", "jio", "airtel"]):
        return "RESIDENTIAL"
    return "DATACENTER"


# ─── LIVE API FETCHERS ────────────────────────────────────────────────────────

def fetch_virustotal_data(indicator: str, ind_type: str, features: PhishingFeatures):
    """Fetches reputation, WHOIS, and first-seen from VirusTotal."""
    if not VT_API_KEY:
        return
    headers = {"x-apikey": VT_API_KEY}
    endpoint = "ip_addresses" if ind_type == "IP" else "domains"

    try:
        resp = SESSION.get(
            f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})

            # Reputation — malicious engine count
            malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
            features.threat_feed_source_count = malicious

            # FIX: inverted confidence score — high malicious count → low confidence (safe)
            # Maps malicious detections (0-90 engines) to 0-100 risk score
            features.confidence_score_stix = min(100, int(malicious * 1.5))

            # FIX: passive_dns_first_seen now populated
            first_seen_ts = attrs.get("first_submission_date") or attrs.get("creation_date")
            if first_seen_ts:
                features.passive_dns_first_seen = datetime.fromtimestamp(
                    first_seen_ts, tz=timezone.utc
                ).isoformat()

            # Domain expiration duration
            if ind_type == "DOMAIN":
                creation   = attrs.get("creation_date")
                expiration = attrs.get("expiration_date")
                if creation and expiration:
                    features.domain_expiration_duration_days = (expiration - creation) // 86400

    except requests.RequestException as e:
        print(f"[!] VT fetch failed for {indicator}: {e}")


def fetch_otx_data(indicator: str, ind_type: str, features: PhishingFeatures):
    """Fetches pulse counts from AlienVault OTX."""
    if not OTX_API_KEY:
        return
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    endpoint = "IPv4" if ind_type == "IP" else "domain"

    try:
        resp = SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/{indicator}/general",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            features.open_threat_exchange_pulse_count = resp.json().get("pulse_info", {}).get("count", 0)
    except requests.RequestException as e:
        print(f"[!] OTX fetch failed for {indicator}: {e}")


def fetch_ipinfo_data(ip: str, features: PhishingFeatures):
    """Fetches ASN and hosting classification from IPInfo."""
    if not IPINFO_TOKEN:
        return
    headers = {"Authorization": f"Bearer {IPINFO_TOKEN}"}
    try:
        resp = SESSION.get(f"https://ipinfo.io/{ip}", headers=headers, timeout=10)
        if resp.status_code == 200:
            org = resp.json().get("org", "")
            features.ip_hosting_type = classify_hosting(org)
    except requests.RequestException as e:
        print(f"[!] IPInfo fetch failed for {ip}: {e}")


# ─── CORE LOGIC PROCESSORS ────────────────────────────────────────────────────

def process_domain(features: PhishingFeatures):
    # 1. Local Heuristics
    clean_name = features.indicator.split('.')[0].lower()
    features.corporate_lookalike_distance = float(min(Levenshtein.distance(clean_name, b) for b in PROTECTED_BRANDS))
    features.url_shortener_used = features.indicator.lower() in SHORTENERS
    try:
        features.indicator.encode('ascii')
        features.brand_homoglyph_detected = "xn--" in features.indicator.lower()
    except UnicodeEncodeError:
        features.brand_homoglyph_detected = True

    # 2. Free APIs (Favicon & crt.sh)
    try:
        cert_resp = SESSION.get(f"https://crt.sh/?q={features.indicator}&output=json", timeout=10)
        if cert_resp.status_code == 200:
            features.certificate_transparency_velocity = len(cert_resp.json())
    except requests.RequestException as e:
        print(f"[!] crt.sh fetch failed: {e}")

    try:
        fav_resp = SESSION.get(f"http://{features.indicator}/favicon.ico", timeout=5, verify=False)
        if fav_resp.status_code == 200:
            features.favicon_hash = str(mmh3.hash(base64.encodebytes(fav_resp.content)))
    except requests.RequestException:
        pass  # favicon absence is non-critical

    # 3. Commercial APIs
    fetch_virustotal_data(features.indicator, "DOMAIN", features)
    fetch_otx_data(features.indicator, "DOMAIN", features)


def process_ip(features: PhishingFeatures):
    # IP-only fields: mark domain-specific fields as not applicable
    features.corporate_lookalike_distance     = None
    features.brand_homoglyph_detected         = None
    features.url_shortener_used               = None
    features.favicon_hash                     = None
    features.certificate_transparency_velocity = None

    features.is_bogon_space = is_bogon(features.indicator)
    if features.is_bogon_space:
        return

    # 1. Free AbuseIPDB
    if ABUSEIPDB_KEY:
        try:
            ab_resp = SESSION.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
                params={'ipAddress': features.indicator, 'maxAgeInDays': 90},
                timeout=10
            )
            if ab_resp.status_code == 200:
                features.hosting_provider_abuse_history = ab_resp.json().get('data', {}).get('totalReports', 0)
        except requests.RequestException as e:
            print(f"[!] AbuseIPDB fetch failed: {e}")

    # 2. Commercial APIs
    fetch_ipinfo_data(features.indicator, features)
    fetch_virustotal_data(features.indicator, "IP", features)
    fetch_otx_data(features.indicator, "IP", features)


# ─── ORCHESTRATOR & I/O ───────────────────────────────────────────────────────

def analyze_indicator(indicator: str) -> dict:
    clean_indicator = sanitize_indicator(indicator)
    ind_type = "IP" if is_ip_address(clean_indicator) else "DOMAIN"
    features = PhishingFeatures(indicator=clean_indicator, indicator_type=ind_type)

    if ind_type == "DOMAIN":
        process_domain(features)
    else:
        process_ip(features)

    # Rate-limit guard: VT free tier = 4 req/min
    time.sleep(VT_RATE_LIMIT_SLEEP)
    return asdict(features)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone Elite 12 Phishing Triage Engine")
    parser.add_argument("-s", "--single",   type=str, help="Scan a single indicator (IP or Domain)")
    parser.add_argument("-m", "--multiple", type=str, help="Scan multiple indicators (comma-separated)")
    parser.add_argument("-f", "--file",     type=str, help="Scan a file containing mixed indicators (one per line)")

    args = parser.parse_args()
    targets_to_scan = []

    if args.single:   targets_to_scan.append(args.single)
    if args.multiple: targets_to_scan.extend(args.multiple.split(","))
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets_to_scan.extend(f.readlines())
        except FileNotFoundError:
            print(f"[!] Error: File '{args.file}' not found.")
            sys.exit(1)

    if not targets_to_scan:
        parser.print_help()
        sys.exit(1)

    print("[*] Initializing Standalone Elite 12 Engine...")
    final_results = []
    for target in targets_to_scan:
        if not target.strip():
            continue
        print(f"[*] Analyzing: {target.strip()}")
        final_results.append(analyze_indicator(target))

    output_filename = "elite12_live_output1.json"
    with open(output_filename, 'w') as f:
        json.dump(final_results, f, indent=4)

    print(f"[+] Scan complete. Analyzed {len(final_results)} indicators.")
    print(f"[+] Results saved to {output_filename}")
