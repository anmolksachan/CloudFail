<img width="1040" height="250" alt="image" src="https://github.com/user-attachments/assets/affedd0c-26ae-48e2-93af-68003f4bcc0f" />

# CloudFail v2.0

> **Cloudflare origin IP discovery tool — 2026 Enhanced Edition**

CloudFail discovers the real origin IP address(es) behind a Cloudflare-protected domain by querying certificate transparency logs, passive DNS databases, and optional paid APIs. It never sends traffic directly to the target during passive mode.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CloudFail v2.0                             │
├─────────────────────────────────────────────────────────────────────┤
│  CLI (__main__.py)                                                  │
│    │                                                                │
│    ├─ Phase 1: Target Init        cloudflare.py                     │
│    │     Resolve domain → check CF membership                      │
│    │     Load/update CF CIDR ranges (JSON API + plain-text fallback)│
│    │                                                                │
│    ├─ Phase 2: Passive Recon      certificate_pivot.py              │
│    │     ┌──────────────────────────────────────────────────┐      │
│    │     │  Free (no API key)         Paid (API key)        │      │
│    │     │  ─────────────────         ───────────────────── │      │
│    │     │  CertSpotter               Censys Platform v3    │      │
│    │     │  crt.sh (retry+backoff)    Shodan                │      │
│    │     │  AnubisDB                  SecurityTrails        │      │
│    │     │  RapidDNS                                        │      │
│    │     │  ThreatMiner                                     │      │
│    │     │  URLScan.io                                      │      │
│    │     │  Wayback Machine CDX                             │      │
│    │     └──────────────────────────────────────────────────┘      │
│    │     + Passive DNS: HackerTarget, AlienVault OTX,              │
│    │                    ViewDNS.info, RapidDNS passive              │
│    │                                                                │
│    ├─ Phase 3: Subdomain Resolution   dns_history.py               │
│    │     CT names + wordlist → dnspython bulk resolve (threads)    │
│    │     Wildcard detection                                         │
│    │                                                                │
│    └─ Phase 4: IP Enrichment          asn_filter.py                │
│          ASN lookup → CF/non-CF classification → confidence score  │
│                                                                     │
│  utils/http_client.py  (ALL HTTP goes through here)                │
│    requests.Session + Retry(total=5, backoff_factor=1)             │
│    Optional Tor SOCKS5 proxy                                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Sources

| Source | Type | API Key | Rate Limit | Notes |
|---|---|---|---|---|
| CertSpotter | CT logs | No | 100 req/hour | Most reliable free CT source |
| crt.sh | CT logs | No | None (rate limited) | Retry+backoff on 502/429 |
| AnubisDB | CT/passive | No | None | Stable JSON endpoint |
| RapidDNS | DNS records | No | None | HTML table extraction |
| ThreatMiner | Passive DNS | No | None | Free JSON API |
| URLScan.io | Page scans | No | 60/min | Free tier |
| Wayback CDX | Historical URLs | No | None | Up to 5000 rows |
| HackerTarget | Passive DNS | No | 100/day | Also used for ASN lookup |
| AlienVault OTX | Passive DNS | No | 429-aware | Backoff+retry on rate limit |
| ViewDNS.info | IP history | No | None | HTML regex extraction |
| Censys Platform API | TLS cert search | **Yes** | Varies | **Requires Starter plan ($99+/mo)** |
| Shodan | TLS cert search | **Yes** | Varies | REST API (free tier available) |
| SecurityTrails | Subdomain enum | **Yes** | Varies | REST API |

---

## Installation

```bash
# Python 3.10–3.12 required
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Optional: Tor support

```bash
# macOS
brew install tor && brew services start tor

# Debian/Ubuntu
sudo apt install tor && sudo service tor start

# Verify Tor is listening on port 9050
nc -zv 127.0.0.1 9050
```

---

## Usage

### Basic scan (no API keys required)

```bash
python -m cloudfail -t example.com --confirm-scope
```

### Full scan with all API keys

```bash
python -m cloudfail -t example.com \
  --censys-api-token YOUR_TOKEN \
  --shodan-api YOUR_KEY \
  --securitytrails-api YOUR_KEY \
  --confirm-scope
```

### Passive only (no DNS bruteforce)

```bash
python -m cloudfail -t example.com --passive-only --confirm-scope
```

### Output to JSON file

```bash
python -m cloudfail -t example.com \
  --output json --output-file results.json --confirm-scope
```

### Route through Tor

```bash
python -m cloudfail -t example.com --tor --confirm-scope
```

### Behind a corporate TLS-inspection proxy

```bash
python -m cloudfail -t example.com --no-verify-ssl --confirm-scope
```

### Debug mode (full tracebacks and HTTP details)

```bash
python -m cloudfail -t example.com --debug --confirm-scope
```

### Quiet mode (results only, no progress messages)

```bash
python -m cloudfail -t example.com --quiet --output json --confirm-scope
```

### Demo

<img width="3452" height="846" alt="image" src="https://github.com/user-attachments/assets/d0601083-bdd9-4901-b1a5-59cdcbd97e83" />
<img width="3442" height="1292" alt="image" src="https://github.com/user-attachments/assets/9f2adccf-9a95-4547-a709-9fd224e18117" />

---

## All CLI Flags

| Flag | Description |
|---|---|
| `-t, --target` | Target domain (required) |
| `--confirm-scope` | Required — confirm authorisation (required) |
| `--passive-only` | Skip subdomain bruteforce |
| `--tor` | Route via Tor SOCKS5 (127.0.0.1:9050) |
| `--no-tor` | Explicitly disable Tor |
| `--no-verify-ssl` | Disable SSL verification |
| `--subdomains FILE` | Custom wordlist path |
| `--threads N` | DNS resolver threads (default: 10) |
| `--update-ranges` | Re-download Cloudflare IP ranges |
| `--censys-api-token` | Censys Platform API Personal Access Token |
| `--shodan-api` | Shodan API key |
| `--securitytrails-api` | SecurityTrails API key |
| `--output text\|json` | Output format (default: text) |
| `--output-file PATH` | Save results to file |
| `--debug` | Enable debug output |
| `--quiet` | Suppress progress messages |

---

## Example JSON Output

```json
{
  "target": "example.com",
  "resolved_ip": "104.21.5.12",
  "behind_cloudflare": true,
  "ct_names": [
    "mail.example.com",
    "api.example.com",
    "staging.example.com"
  ],
  "passive_dns_ips": ["203.0.113.42", "198.51.100.7"],
  "non_cloudflare_ips": [
    {
      "ip": "203.0.113.42",
      "asn": "AS12345",
      "is_cloudflare": "no",
      "confidence": "90"
    }
  ],
  "subdomain_hits": [
    { "host": "staging.example.com", "ip": "203.0.113.42", "behind_cloudflare": false },
    { "host": "www.example.com",     "ip": "104.21.5.12",  "behind_cloudflare": true  }
  ]
}
```

---

## Error Resilience

CloudFail is designed to **never crash** because a single data source fails:

| Failure | Behaviour |
|---|---|
| crt.sh returns 502 | Retry up to 5 times with exponential backoff; log warning and continue |
| crt.sh returns 429 | Backoff and retry; continue with other sources |
| AlienVault OTX 429 | Backoff 4s / 8s / skip; never crash phase |
| Censys 302 redirect | `allow_redirects=True` follows automatically |
| Censys 401/403 | Log descriptive message; skip gracefully |
| Any API unavailable | Warning logged; scan continues |
| DNS resolution timeout | dnspython per-resolver timeout; returns None |
| Wildcard DNS | Detected and warned; CT names still valid |
| Network unreachable | Exception caught; warning logged |
| Tor not running | Log error; continue without Tor |

---

## Rate Limit Notes

| Source | Limit | Behaviour on Limit |
|---|---|---|
| CertSpotter | 100 req/hour | Warning logged |
| HackerTarget | 100 req/day | Warning with API key upgrade note |
| AlienVault OTX | Variable | 429 → backoff 4s, 8s, then skip |
| URLScan.io | 60/min free | 429 → warning + skip |
| ThreatMiner | Shared rate | 429 → warning + skip |
| Censys v2 | Quota-based | 429 → stop pagination |
| Shodan | Credit-based | 401 → invalid key warning |

---

## Tor Usage

When `--tor` is specified:

1. The shared `requests.Session` is reconfigured to use `socks5h://127.0.0.1:9050`
2. Connectivity is verified via `https://check.torproject.org/api/ip`
3. All subsequent HTTP calls (including DNS-over-HTTPS style) route through Tor
4. Requires: `pip install PySocks` and a running Tor service

> **Note:** DNS resolution via `dnspython` uses system resolvers, not the HTTP proxy. For fully anonymous DNS, run a local DNS-over-Tor setup or use `--passive-only` with Tor.

---

## Confidence Scoring

| Score | Meaning |
|---|---|
| 95% | IP is in a Cloudflare CIDR block (definitive CF match) |
| 90% | IP is NOT in any CF range and ASN is not AS13335 |
| 70% | IP not in CF range but ASN matches AS13335 (possible new range) |
| 0% | ASN lookup failed — treat as unknown |

---

## Troubleshooting

### `Could not load Cloudflare IP ranges`

```bash
# Force fresh download and disable SSL verification
python -m cloudfail -t example.com --update-ranges --no-verify-ssl --confirm-scope
```

### `crt.sh returning many 502 errors`

crt.sh can be slow under load. CloudFail retries automatically (5 attempts, exponential backoff). Other sources (CertSpotter, AnubisDB, RapidDNS etc.) will still return data.

### `AlienVault OTX always 429`

OTX rate limits anonymous access. CloudFail backs off and skips OTX after 3 failures. Other passive DNS sources continue. Consider registering for a free OTX API key.

### `Censys authentication errors`

**Updated for 2026:** Censys now uses the Platform API v3 with Personal Access Tokens (Bearer tokens). Generate your token at `https://accounts.censys.io/settings/personal-access-tokens`. Note: Free users can only use lookup endpoints, not search — you need a Starter or Enterprise plan to search hosts.

### `No results at all`

- Try `--debug` to see full HTTP responses
- Try `--no-verify-ssl` if behind a corporate proxy
- Check your internet connection can reach external APIs

### HackerTarget daily limit

HackerTarget limits anonymous requests to 100/day. The ASN enrichment phase uses one HackerTarget call per non-CF IP. For large scans register for a free API key at `hackertarget.com`.

---

## Performance Notes

- Phase 2 passive sources run **concurrently** (5 threads by default)
- Phase 3 subdomain resolution runs with `--threads` workers (default: 10)
- Typical full scan of a large domain: 3–8 minutes
- Use `--passive-only` to skip the ~11k subdomain wordlist and reduce to 1–2 minutes
- Use `--threads 25` to speed up subdomain resolution (watch for DNS resolver bans)

---

## API Quota Warnings

- **Censys v2 free tier**: limited monthly query quota — check `search.censys.io/account`
- **Shodan free tier**: host search is a paid feature; you need a paid plan or use the membership API
- **SecurityTrails free tier**: 50 API calls/month on free plan
- **HackerTarget**: 100 free queries/day across all their endpoints combined

---

## Project Structure

```
CloudFail-main/
├── requirements.txt
├── README.md
└── cloudfail/
    ├── __init__.py
    ├── __main__.py          # CLI entry point, phase orchestration
    ├── config.py            # Constants, runtime state
    ├── data/
    │   ├── subdomains.txt   # Built-in ~11k subdomain wordlist
    │   └── cf-subnet.txt    # Cached Cloudflare CIDR ranges (auto-generated)
    ├── core/
    │   ├── cloudflare.py    # CF range management, IP detection
    │   ├── certificate_pivot.py  # CT + passive sources + Censys/Shodan/ST
    │   ├── dns_history.py   # DNS resolution + passive DNS aggregation
    │   ├── asn_filter.py    # ASN lookup, IP enrichment
    │   └── tor_handler.py   # Tor SOCKS5 proxy configuration
    └── utils/
        ├── http_client.py   # Centralised HTTP session (ALL requests here)
        └── logger.py        # Rich-based logger with debug/quiet modes
```

---

## Legal Disclaimer

This tool is provided for **authorized security testing and research purposes only**.

- You must have explicit written permission from the asset owner before scanning
- Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction
- The authors accept no liability for misuse of this tool
- Cloudflare's ToS prohibits intentional origin IP discovery against protected customers
- Use responsibly and ethically

---

## Contribution Guide

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-source`
3. Add your data source in `certificate_pivot.py` or `dns_history.py`
4. Ensure it:
   - Uses `http_client.get()` — never `requests.get()` directly
   - Has timeout handling
   - Returns an empty list/set on any failure (never raises)
   - Has a `logger.info/warning` for rate limits
   - Has a `logger.debug_exc()` call in the except block
5. Add it to the concurrent source map in the aggregation function
6. Update the data sources table in README.md
7. Submit a PR

---

## License

MIT License — see original CloudFail repository for full text.

Original CloudFail by [m0rtem](https://github.com/m0rtem/CloudFail) (2018).  
v2.0 Enhanced Edition (2026).
