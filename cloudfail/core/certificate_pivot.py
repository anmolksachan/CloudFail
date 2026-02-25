"""
CloudFail v2.0 — Certificate Transparency & host discovery

Passive CT Sources (no API key required):
  1. CertSpotter (SSLMate)  — 100 req/hour free tier
  2. crt.sh                 — wildcard + direct fallback, retry+backoff
  3. AnubisDB               — free, reliable JSON endpoint
  4. RapidDNS               — free JSON API
  5. ThreatMiner            — free passive DNS API
  6. URLScan.io             — search API, free tier
  7. Wayback Machine CDX    — historical domain data

Paid/key-required sources:
  8. Censys Platform API v3 (POST search with Bearer token)
  9. Shodan
  10. SecurityTrails
"""
from __future__ import annotations

import concurrent.futures
import time
from typing import List, Optional, Set

import cloudfail.config as _cfg
from cloudfail.utils import logger, http_client


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clean_names(raw_names: List[str], domain: str) -> Set[str]:
    """Deduplicate, normalise, and filter a flat list of DNS name strings."""
    found: Set[str] = set()
    for name in raw_names:
        name = str(name).strip().lstrip("*.")
        if name and domain.lower() in name.lower() and " " not in name:
            found.add(name.lower())
    return found


def _backoff_sleep(attempt: int, base: float = 2.0) -> None:
    """Exponential backoff sleep: 2^attempt seconds."""
    delay = base ** attempt
    logger.debug(f"Backoff sleep {delay:.1f}s (attempt {attempt})")
    time.sleep(delay)


# ---------------------------------------------------------------------------
# Source 1: CertSpotter  (primary — most reliable free CT source)
# ---------------------------------------------------------------------------

def _certspotter(domain: str) -> Set[str]:
    found: Set[str] = set()
    try:
        resp = http_client.get(
            "https://api.certspotter.com/v1/issuances",
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            timeout=30,
        )
        if resp.status_code == 200:
            for cert in resp.json():
                for name in cert.get("dns_names", []):
                    name = name.strip().lstrip("*.")
                    if name and domain.lower() in name.lower():
                        found.add(name.lower())
            logger.info(f"[CertSpotter] Found {len(found)} names.")
        elif resp.status_code == 429:
            logger.warning("[CertSpotter] Rate limited (100 req/hour free tier).")
        else:
            logger.warning(f"[CertSpotter] HTTP {resp.status_code}.")
    except Exception as exc:
        logger.warning(f"[CertSpotter] {exc}")
        logger.debug_exc(exc, "CertSpotter")
    return found


# ---------------------------------------------------------------------------
# Source 2: crt.sh  — retry with exponential backoff, dual query paths
# ---------------------------------------------------------------------------

def _crtsh(domain: str) -> Set[str]:
    found: Set[str] = set()

    def _parse(entries: list) -> None:
        for entry in entries:
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain.lower() in name.lower() and " " not in name:
                    found.add(name.lower())

    urls = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]

    for url in urls:
        if found:
            break
        for attempt in range(5):
            try:
                resp = http_client.get(url, timeout=45)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        _parse(data)
                        if found:
                            logger.info(f"[crt.sh] Found {len(found)} names.")
                    except ValueError as exc:
                        logger.warning(f"[crt.sh] JSON parse error: {exc}")
                    break
                elif resp.status_code in (429, 500, 502, 503, 504):
                    logger.warning(
                        f"[crt.sh] HTTP {resp.status_code} — "
                        f"backoff attempt {attempt + 1}/5"
                    )
                    _backoff_sleep(attempt)
                else:
                    logger.warning(f"[crt.sh] HTTP {resp.status_code}.")
                    break
            except Exception as exc:
                logger.warning(f"[crt.sh] Attempt {attempt + 1}: {exc}")
                logger.debug_exc(exc, "crt.sh")
                if attempt < 4:
                    _backoff_sleep(attempt)

    return found


# ---------------------------------------------------------------------------
# Source 3: AnubisDB  — free, reliable, JSON endpoint
# ---------------------------------------------------------------------------

def _anubisdb(domain: str) -> Set[str]:
    found: Set[str] = set()
    try:
        resp = http_client.get(
            f"https://jldc.me/anubis/subdomains/{domain}",
            timeout=20,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for name in data:
                    name = str(name).strip().lstrip("*.")
                    if name and domain.lower() in name.lower():
                        found.add(name.lower())
            logger.info(f"[AnubisDB] Found {len(found)} names.")
        else:
            logger.warning(f"[AnubisDB] HTTP {resp.status_code}.")
    except Exception as exc:
        logger.warning(f"[AnubisDB] {exc}")
        logger.debug_exc(exc, "AnubisDB")
    return found


# ---------------------------------------------------------------------------
# Source 4: RapidDNS  — free JSON API, good coverage
# ---------------------------------------------------------------------------

def _rapiddns(domain: str) -> Set[str]:
    found: Set[str] = set()
    try:
        resp = http_client.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1&down=1",
            headers={"Accept": "text/html,application/xhtml+xml"},
            timeout=20,
        )
        if resp.status_code == 200:
            import re
            # RapidDNS returns an HTML table; extract subdomains
            matches = re.findall(
                r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>',
                resp.text,
            )
            for name in matches:
                name = name.strip().lower()
                if name:
                    found.add(name)
            logger.info(f"[RapidDNS] Found {len(found)} names.")
        else:
            logger.warning(f"[RapidDNS] HTTP {resp.status_code}.")
    except Exception as exc:
        logger.warning(f"[RapidDNS] {exc}")
        logger.debug_exc(exc, "RapidDNS")
    return found


# ---------------------------------------------------------------------------
# Source 5: ThreatMiner  — free passive DNS
# ---------------------------------------------------------------------------

def _threatminer(domain: str) -> Set[str]:
    found: Set[str] = set()
    try:
        resp = http_client.get(
            "https://api.threatminer.org/v2/domain.php",
            params={"q": domain, "rt": "5"},
            timeout=20,
        )
        if resp.status_code == 200:
            data = resp.json()
            status = str(data.get("status_code", ""))
            if status == "200":
                for name in data.get("results", []):
                    name = str(name).strip().lstrip("*.")
                    if name and domain.lower() in name.lower():
                        found.add(name.lower())
                logger.info(f"[ThreatMiner] Found {len(found)} names.")
            elif status == "404":
                logger.debug(f"[ThreatMiner] No results for {domain}.")
            else:
                logger.warning(f"[ThreatMiner] API status: {status}.")
        elif resp.status_code == 429:
            logger.warning("[ThreatMiner] Rate limited — skipping.")
        else:
            logger.warning(f"[ThreatMiner] HTTP {resp.status_code}.")
    except Exception as exc:
        logger.warning(f"[ThreatMiner] {exc}")
        logger.debug_exc(exc, "ThreatMiner")
    return found


# ---------------------------------------------------------------------------
# Source 6: URLScan.io  — free search API
# ---------------------------------------------------------------------------

def _urlscan(domain: str) -> Set[str]:
    found: Set[str] = set()
    try:
        resp = http_client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 100},
            timeout=20,
        )
        if resp.status_code == 200:
            data = resp.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                hostname = page.get("domain", "")
                if hostname and domain.lower() in hostname.lower():
                    found.add(hostname.lower().lstrip("*."))
            logger.info(f"[URLScan] Found {len(found)} names.")
        elif resp.status_code == 429:
            logger.warning("[URLScan] Rate limited — skipping.")
        else:
            logger.warning(f"[URLScan] HTTP {resp.status_code}.")
    except Exception as exc:
        logger.warning(f"[URLScan] {exc}")
        logger.debug_exc(exc, "URLScan")
    return found


# ---------------------------------------------------------------------------
# Source 7: Wayback Machine CDX  — historical domain data
# ---------------------------------------------------------------------------

def _wayback_cdx(domain: str) -> Set[str]:
    found: Set[str] = set()
    try:
        resp = http_client.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": 5000,
            },
            timeout=30,
        )
        if resp.status_code == 200:
            import re
            subdomain_re = re.compile(
                r"(?:https?://)?([a-zA-Z0-9._-]+\." + re.escape(domain) + r")"
            )
            for row in resp.json():
                for cell in row:
                    m = subdomain_re.search(str(cell))
                    if m:
                        name = m.group(1).strip().lower()
                        found.add(name)
            logger.info(f"[WaybackCDX] Found {len(found)} names.")
        else:
            logger.warning(f"[WaybackCDX] HTTP {resp.status_code}.")
    except Exception as exc:
        logger.warning(f"[WaybackCDX] {exc}")
        logger.debug_exc(exc, "WaybackCDX")
    return found


# ---------------------------------------------------------------------------
# Combined CT aggregation
# ---------------------------------------------------------------------------

def crtsh_subdomains(domain: str) -> List[str]:
    """
    Collect certificate transparency / passive DNS names from all free sources.
    Sources run concurrently; results are merged and deduplicated.
    """
    logger.info(f"[CT/Passive] Querying all passive sources for {domain}…")
    all_found: Set[str] = set()

    sources = {
        "CertSpotter": _certspotter,
        "crt.sh":      _crtsh,
        "AnubisDB":    _anubisdb,
        "RapidDNS":    _rapiddns,
        "ThreatMiner": _threatminer,
        "URLScan":     _urlscan,
        "WaybackCDX":  _wayback_cdx,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in sources.items()}
        for future in concurrent.futures.as_completed(futures):
            src_name = futures[future]
            try:
                result = future.result()
                all_found.update(result)
            except Exception as exc:
                logger.warning(f"[CT/{src_name}] Unexpected error: {exc}")
                logger.debug_exc(exc, src_name)

    logger.info(f"[CT/Passive] Total unique names across all sources: {len(all_found)}")
    return sorted(all_found)


# ---------------------------------------------------------------------------
# Censys Platform API v3 (direct POST to search endpoint)
# ---------------------------------------------------------------------------

def censys_hosts(
    domain: str,
    api_token: Optional[str] = None,
) -> List[str]:
    """
    Search Censys Platform API v3 for hosts with TLS certificates matching *domain*.

    Uses Bearer Token authentication as documented at:
    https://docs.censys.com/reference/get-started

    New API (2024+):
      - URL: https://api.platform.censys.io/v3/global/search/query
      - Method: POST with JSON body
      - Auth: Bearer token (Personal Access Token)

    Handles:
      - 401/403 auth errors (skip gracefully)
      - 422 query errors
      - 429 rate limits (stop pagination)
      - Pagination using page_token
    """
    if not api_token:
        return []

    logger.info(f"[Censys] Searching for hosts matching {domain}…")
    ips: List[str] = []

    try:
        auth_header = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        page_token: Optional[str] = None
        pages_fetched = 0
        max_pages = 5

        # Query for hosts with certificates containing the target domain
        query = f'services.tls.certificates.leaf_data.names: "{domain}"'

        while pages_fetched < max_pages:
            body = {
                "query": query,
                "page_size": 100,
                "fields": ["host.ip"],
            }
            if page_token:
                body["page_token"] = page_token

            resp = http_client.post(
                "https://api.platform.censys.io/v3/global/search/query",
                json=body,
                headers=auth_header,
                timeout=30,
            )

            if resp.status_code == 401:
                logger.warning(
                    "[Censys] Authentication failed (401). "
                    "Generate a Personal Access Token at: https://accounts.censys.io/settings/personal-access-tokens"
                )
                break
            elif resp.status_code == 403:
                error_detail = ""
                try:
                    error_data = resp.json()
                    error_detail = error_data.get("detail", "")
                except:
                    pass
                
                if "Free users" in error_detail or "organization ID" in error_detail:
                    logger.warning(
                        "[Censys] Free tier limitation: Search API requires a paid plan (Starter/Enterprise).\n"
                        "         Free users can only use lookup endpoints via the web UI.\n"
                        "         Upgrade at: https://censys.com/pricing\n"
                        "         CloudFail will continue with other free sources..."
                    )
                else:
                    logger.warning(f"[Censys] Access denied (403): {error_detail or 'Check permissions'}")
                break
            elif resp.status_code == 422:
                logger.warning(f"[Censys] Invalid query (422): {resp.text[:200]}")
                break
            elif resp.status_code == 429:
                logger.warning("[Censys] Rate limited (429). Stopping pagination.")
                break
            elif resp.status_code != 200:
                logger.warning(f"[Censys] HTTP {resp.status_code}: {resp.text[:200]}")
                break

            data = resp.json()
            hits = data.get("results", [])
            
            for hit in hits:
                # Extract IP from nested structure
                host_data = hit.get("host", {})
                ip = host_data.get("ip")
                if ip:
                    ips.append(ip)

            # Check for pagination token
            next_token = data.get("page_token")
            if not next_token or not hits:
                break
            page_token = next_token
            pages_fetched += 1

    except Exception as exc:
        logger.warning(f"[Censys] Error: {exc}")
        logger.debug_exc(exc, "Censys")

    logger.info(f"[Censys] Found {len(ips)} host IPs.")
    return ips


# ---------------------------------------------------------------------------
# Shodan  (optional, requires API key)
# ---------------------------------------------------------------------------

def shodan_hosts(domain: str, api_key: Optional[str] = None) -> List[str]:
    """Use Shodan REST API to find IPs with *domain* in their SSL/TLS cert."""
    if not api_key:
        return []

    logger.info(f"[Shodan] Searching for hosts matching {domain}…")
    ips: List[str] = []
    
    try:
        # Shodan API is behind Cloudflare - use minimal headers to avoid blocking
        import requests as _req
        import time
        time.sleep(0.5)  # Small delay to avoid triggering rate limits
        
        # Try primary query
        resp = _req.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key": api_key,
                "query": f"ssl.cert.subject.cn:{domain}",
            },
            timeout=25,
        )
        if resp.status_code == 200:
            for match in resp.json().get("matches", []):
                ip = match.get("ip_str")
                if ip:
                    ips.append(ip)
        elif resp.status_code == 401:
            logger.warning("[Shodan] Invalid API key (401).")
        elif resp.status_code == 403:
            # Check if it's Cloudflare blocking
            if "cloudflare" in resp.text.lower() or "<!DOCTYPE html>" in resp.text:
                logger.warning(
                    "[Shodan] Request blocked by Cloudflare protection (403). "
                    "Try again after a few seconds or use Shodan web interface."
                )
            else:
                logger.warning("[Shodan] Access forbidden (403). Check your API key permissions.")
        elif resp.status_code == 429:
            logger.warning("[Shodan] Rate limited (429).")
        else:
            logger.warning(f"[Shodan] HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logger.warning(f"[Shodan] Error: {exc}")
        logger.debug_exc(exc, "Shodan")

    logger.info(f"[Shodan] Found {len(ips)} host IPs.")
    return ips


# ---------------------------------------------------------------------------
# SecurityTrails  (optional, requires API key)
# ---------------------------------------------------------------------------

def securitytrails_subdomains(
    domain: str,
    api_key: Optional[str] = None,
) -> List[str]:
    """Query SecurityTrails API for all known subdomains of *domain*."""
    if not api_key:
        return []

    logger.info(f"[SecurityTrails] Querying subdomains for {domain}…")
    subdomains: List[str] = []
    try:
        resp = http_client.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": api_key},
            timeout=25,
        )
        if resp.status_code == 200:
            for sub in resp.json().get("subdomains", []):
                subdomains.append(f"{sub}.{domain}")
        elif resp.status_code == 401:
            logger.warning("[SecurityTrails] Invalid API key (401).")
        elif resp.status_code == 429:
            logger.warning("[SecurityTrails] Rate limited (429).")
        else:
            logger.warning(
                f"[SecurityTrails] HTTP {resp.status_code}: {resp.text[:200]}"
            )
    except Exception as exc:
        logger.warning(f"[SecurityTrails] Error: {exc}")
        logger.debug_exc(exc, "SecurityTrails")

    logger.info(f"[SecurityTrails] Found {len(subdomains)} subdomains.")
    return subdomains
