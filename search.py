#!/usr/bin/env python3
"""
MEGATRON - search.py
Free web search via DuckDuckGo — no API key needed.
Also fetches and extracts plain text from URLs.
Used by LLM tool dispatch when AI writes [SEARCH: query]
"""

import re
import time
import requests
from bs4 import BeautifulSoup
from ddgs import DDGS   # pip install duckduckgo-search

_NVD_CACHE: dict[str, dict | None] = {}
_NVD_LAST_CALL_TS: float = 0.0
_NVD_MIN_INTERVAL_S: float = 6.5   # free tier: 5 req / 30s → 6s spacing is safe
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE  = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


# ─────────────────────────────────────────────
# DDG SEARCH
# ─────────────────────────────────────────────

def web_search(query: str, max_results: int = 5) -> str:
    """
    Search DuckDuckGo and return formatted results.
    No API key. No rate limit issues for reasonable usage.
    Returns a string ready to paste into LLM prompt.
    """
    print(f"  [*] Searching: {query}")
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "[!] No search results found."

        output = f"[WEB SEARCH RESULTS FOR: {query}]\n"
        output += "─" * 50 + "\n"
        for i, r in enumerate(results, 1):
            output += f"\n[{i}] {r['title']}\n"
            output += f"    URL     : {r['href']}\n"
            output += f"    Snippet : {r['body']}\n"

        return output

    except Exception as e:
        return f"[!] Search failed: {e}"


# ─────────────────────────────────────────────
# CVE SPECIFIC SEARCH
# ─────────────────────────────────────────────

def search_cve(cve_id: str) -> str:
    """
    Search for a specific CVE.
    Queries DDG then also hits cve.mitre.org directly.
    """
    print(f"  [*] Looking up {cve_id}...")

    # DDG search first
    ddg_results = web_search(f"{cve_id} vulnerability exploit details", max_results=3)

    # Direct MITRE fetch
    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    mitre_data = fetch_page(mitre_url, max_chars=2000)

    return f"{ddg_results}\n\n[MITRE CVE LOOKUP: {cve_id}]\n{mitre_data}"


def search_exploit(service: str, version: str) -> str:
    """
    Search for known exploits for a service + version combo.
    e.g. search_exploit("apache", "2.4.49")
    """
    query = f"{service} {version} exploit CVE vulnerability 2023 2024"
    return web_search(query, max_results=5)


def search_fix(vuln_name: str) -> str:
    """
    Search for mitigation/fix for a vulnerability.
    """
    query = f"how to fix {vuln_name} security mitigation patch"
    return web_search(query, max_results=3)


# ─────────────────────────────────────────────
# PAGE FETCHER
# ─────────────────────────────────────────────

def fetch_page(url: str, max_chars: int = 3000) -> str:
    """
    Fetch a URL and return extracted plain text.
    Strips all HTML tags. Truncated to max_chars for LLM context.
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        # remove nav/footer/script noise
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        text = soup.get_text(separator="\n", strip=True)

        # collapse blank lines
        lines = [l for l in text.splitlines() if l.strip()]
        clean = "\n".join(lines)

        if len(clean) > max_chars:
            clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"

        return clean

    except requests.exceptions.ConnectionError:
        return "[!] Could not connect to URL — check network."
    except requests.exceptions.Timeout:
        return "[!] Page fetch timed out."
    except requests.exceptions.HTTPError as e:
        return f"[!] HTTP error: {e}"
    except Exception as e:
        return f"[!] Fetch failed: {e}"


# ─────────────────────────────────────────────
# TOOL DISPATCH HANDLER
# ─────────────────────────────────────────────

def handle_search_dispatch(query: str) -> str:
    """
    Called by llm.py when AI writes [SEARCH: something].
    Smartly routes to CVE lookup, exploit search, or general search.
    """
    query = query.strip()

    # CVE pattern — CVE-YYYY-NNNNN
    import re
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cve_match = cve_pattern.search(query)
    if cve_match:
        return search_cve(cve_match.group())

    # exploit keywords
    if any(word in query.lower() for word in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        return web_search(query + " exploit poc github", max_results=5)

    # fix/patch keywords
    if any(word in query.lower() for word in ["fix", "patch", "mitigate", "harden", "secure"]):
        return search_fix(query)

    # default general search
    return web_search(query, max_results=5)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ search.py test ]\n")
    print("[1] General search")
    print("[2] CVE lookup")
    print("[3] Fetch a URL")
    choice = input("Choice: ").strip()

    if choice == "1":
        q = input("Query: ").strip()
        print(web_search(q))

    elif choice == "2":
        cve = input("CVE ID (e.g. CVE-2021-44228): ").strip()
        print(search_cve(cve))

    elif choice == "3":
        url = input("URL: ").strip()
        print(fetch_page(url))

    elif choice == "4":
        cve = input("CVE ID to verify against NVD: ").strip()
        result = verify_cve_nvd(cve)
        print(result if result else "[!] Not found in NVD (or invalid ID).")


# ─────────────────────────────────────────────
# NVD API - CVE GROUNDING
# ─────────────────────────────────────────────

def verify_cve_nvd(cve_id: str) -> dict | None:
    """
    Check that a CVE ID actually exists in the NIST NVD.
    Returns dict with {id, cvss, summary, published} on hit; None on miss/invalid.
    Cached in-process. Free tier rate-limited to 5 req / 30s → we self-throttle to 6s.
    """
    global _NVD_LAST_CALL_TS
    if not cve_id or not _CVE_RE.match(cve_id):
        return None
    cve_id = cve_id.upper()
    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[cve_id]

    delta = time.monotonic() - _NVD_LAST_CALL_TS
    if delta < _NVD_MIN_INTERVAL_S:
        time.sleep(_NVD_MIN_INTERVAL_S - delta)

    try:
        r = requests.get(_NVD_API, params={"cveId": cve_id}, timeout=15,
                         headers={"User-Agent": "MEGATRON/2.0"})
        _NVD_LAST_CALL_TS = time.monotonic()
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"  [NVD] request failed for {cve_id}: {e}")
        _NVD_CACHE[cve_id] = None
        return None

    try:
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            _NVD_CACHE[cve_id] = None
            return None
        cve = vulns[0]["cve"]
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        summary = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                break
        result = {
            "id":        cve_id,
            "cvss":      cvss,
            "summary":   summary[:400],
            "published": cve.get("published", ""),
        }
        _NVD_CACHE[cve_id] = result
        return result
    except (KeyError, ValueError, TypeError) as e:
        print(f"  [NVD] parse error for {cve_id}: {e}")
        _NVD_CACHE[cve_id] = None
        return None


def nvd_search_by_product(product: str, version: str = "", limit: int = 5) -> list[dict]:
    """
    Proactive CVE lookup: given a detected service (product name + optional version),
    ask NVD for recent CVEs. Used by llm.py to inject grounded CVEs the LLM was too
    conservative to claim on its own (e.g., Apache 2.4.49 -> CVE-2021-41773).

    Returns list of {id, cvss, summary, published} dicts, empty on miss.
    Cached per (product, version) pair. Self-throttled to NVD's 5 req / 30s free tier.
    """
    global _NVD_LAST_CALL_TS
    if not product or len(product) < 3:
        return []

    cache_key = f"__prod__{product.lower()}::{version}"
    if cache_key in _NVD_CACHE:
        cached = _NVD_CACHE[cache_key]
        return cached if isinstance(cached, list) else []

    delta = time.monotonic() - _NVD_LAST_CALL_TS
    if delta < _NVD_MIN_INTERVAL_S:
        time.sleep(_NVD_MIN_INTERVAL_S - delta)

    if version:
        params = {
            "virtualMatchString": f"cpe:2.3:a:*:{product.lower()}:{version}:*:*:*:*:*:*:*",
            "resultsPerPage": str(limit),
        }
    else:
        params = {"keywordSearch": product, "resultsPerPage": str(limit)}

    try:
        r = requests.get(_NVD_API, params=params, timeout=15,
                         headers={"User-Agent": "MEGATRON/2.0"})
        _NVD_LAST_CALL_TS = time.monotonic()
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"  [NVD] product search failed for {product} {version}: {e}")
        _NVD_CACHE[cache_key] = []
        return []

    findings: list[dict] = []
    try:
        for v in r.json().get("vulnerabilities", [])[:limit]:
            cve = v["cve"]
            metrics = cve.get("metrics", {})
            cvss = None
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in metrics and metrics[k]:
                    cvss = metrics[k][0].get("cvssData", {}).get("baseScore")
                    break
            summary = next(
                (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            findings.append({
                "id":        cve["id"],
                "cvss":      cvss,
                "summary":   summary[:300],
                "published": cve.get("published", ""),
            })
    except (KeyError, ValueError, TypeError) as e:
        print(f"  [NVD] parse error on product search {product}: {e}")
        _NVD_CACHE[cache_key] = []
        return []

    findings.sort(key=lambda f: f.get("cvss") or 0, reverse=True)
    _NVD_CACHE[cache_key] = findings
    return findings
