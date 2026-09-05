#!/usr/bin/env python3
"""
MEGATRON - tools.py  (v2.0 - modern recon stack)

Tool inventory:
  Classic  : nmap, whois, whatweb, curl, dig, nikto
  Modern   : naabu (fast port sweep), httpx-pd (web probe/tech),
             nuclei (8k+ CVE templates)
Also adds:
  - Two-stage pipeline `run_recon_pipeline`: naabu → nmap deep on found ports
  - UDP top-100 sweep for SNMP/DNS/TFTP/IPMI (competition classics)
  - Softer nmap timing (-T3) to avoid DoS'ing fragile CTF boxes
"""

from __future__ import annotations
import json
import re
import socket
import subprocess

TLS_SUSPECT_PORTS = {443, 465, 636, 993, 995, 5061, 6697, 8443, 9443, 7443}
WEB_SUSPECT_PORTS = {80, 443, 3000, 5000, 7443, 8000, 8008, 8080, 8443, 8888, 9000, 9090}


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = 120) -> str:
    """Execute a shell command, return combined stdout+stderr. Never crashes."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        output, errors = result.stdout.strip(), result.stderr.strip()
        if output and errors:
            return output + "\n[STDERR]\n" + errors
        return output or errors or "[!] Tool returned no output."
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(command)}"
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]} — install it (see tools.py header)."
    except Exception as e:
        return f"[!] Unexpected error running {command[0]}: {e}"


# ─────────────────────────────────────────────
# CLASSIC TOOLS (kept, with softer timing)
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    """
    nmap -sV -sC -T3 --open  (softer than -T4; T4 DoSes fragile CTF hosts)
    """
    print(f"  [*] nmap -sV -sC -T3 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T3", "--open", target], timeout=300)


def run_nmap_udp_top100(target: str) -> str:
    """UDP top-100 sweep — catches SNMP/DNS/TFTP/IPMI/NetBIOS-name."""
    print(f"  [*] nmap -sU --top-ports 100 -T3 --open {target}")
    return run_tool(["nmap", "-sU", "--top-ports", "100", "-T3", "--open", target], timeout=600)


def run_whois(target: str) -> str:
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_whatweb(target: str) -> str:
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def run_curl_headers(target: str) -> str:
    """curl -sI on http + https. Kept for parity with old menu."""
    print(f"  [*] curl -sI http://{target} + https://{target}")
    http  = run_tool(["curl", "-sI", "--max-time", "10", "--location", f"http://{target}"],  timeout=20)
    https = run_tool(["curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{target}"], timeout=20)
    return f"[HTTP Headers]\n{http}\n\n[HTTPS Headers]\n{https}"


def run_dig(target: str) -> str:
    print(f"  [*] dig {target} (A/MX/NS/TXT)")
    parts = {}
    for rrtype in ("A", "MX", "NS", "TXT"):
        parts[rrtype] = run_tool(["dig", "+short", rrtype, target], timeout=15)
    return "\n\n".join(f"[{k} Records]\n{v}" for k, v in parts.items())


def run_nikto(target: str) -> str:
    """Legacy web vuln scanner. Slower + noisier than nuclei; kept as secondary."""
    print(f"  [*] nikto -h {target}")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)


# ─────────────────────────────────────────────
# GROUND-TRUTH PROBES (verify what naabu/nmap claim)
# ─────────────────────────────────────────────

def _tcp_verify(target: str, port: int, timeout: float = 3.0) -> bool:
    """
    Ground-truth check that a port really accepts. Two-stage:
      1) raw TCP socket handshake — kills naabu SYN-scan false positives
      2) fallback: HTTP HEAD via curl — catches docker's dynamic-port range (>=32768)
         where the kernel's TCP semantics interact oddly with docker's user-mode
         proxy (loopback publishing can look "filtered" to a raw socket but serve
         HTTP fine). Bug seen v0.5.2 XBOW baseline on 127.0.0.1:32770.
    """
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    if port < 1024 and port not in (80, 443, 8080, 8443):
        return False
    for scheme in ("http", "https"):
        r = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "3", f"{scheme}://{target}:{port}/"],
            capture_output=True, text=True, timeout=5,
        )
        if r.stdout.strip().isdigit() and int(r.stdout.strip()) > 0:
            return True
    return False


def run_tls_cert(target: str, port: int) -> str:
    """
    openssl s_client -> x509. TLS cert subject/issuer/SAN is the single highest-signal
    service fingerprint we can grab in one command. CN often names the product exactly
    (e.g., 'CN=asterisk.local', 'CN=vcenter.example.com', 'CN=UniFi').
    """
    print(f"  [*] tls-cert on {target}:{port}")
    cmd = (
        f"echo | timeout 10 openssl s_client -connect {target}:{port} "
        f"-servername {target} 2>/dev/null | "
        f"openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>&1"
    )
    out = run_tool(["bash", "-c", cmd], timeout=20)
    if not out or "unable to load certificate" in out.lower():
        return f"[tls-cert {port}] no certificate returned (not TLS or handshake failed)"
    return f"[tls-cert {port}]\n{out}"


def probe_ssh_banner(target: str, port: int = 22) -> str:
    """
    Classify port 22 behavior: real SSH, tarpit (endlessh), honeypot (cowrie),
    proxy stall, or plain empty accept. Real sshd sends 'SSH-2.0-...' within ms;
    silence > 5s = anomaly worth surfacing to the LLM.
    """
    print(f"  [*] ssh-banner probe on {target}:{port}")
    try:
        with socket.create_connection((target, port), timeout=3.0) as s:
            s.settimeout(5.0)
            try:
                banner = s.recv(256).decode("utf-8", errors="replace").strip()
                if banner.startswith("SSH-"):
                    return f"[ssh-probe {port}] REAL_SSH banner: {banner}"
                if not banner:
                    return f"[ssh-probe {port}] EMPTY_ACCEPT (opens then closes silently — proxy or filtered)"
                return f"[ssh-probe {port}] NON_SSH_DATA: {banner!r} (impersonation / wrong service on this port)"
            except socket.timeout:
                return (
                    f"[ssh-probe {port}] TARPIT_SUSPECT (opens TCP but no data in 5s — "
                    f"likely endlessh/cowrie/honeypot or intentional stall)"
                )
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return f"[ssh-probe {port}] UNREACHABLE: {e}"


# ─────────────────────────────────────────────
# MODERN TOOLS (2024-2026)
# ─────────────────────────────────────────────

def run_naabu(target: str, top_ports: str = "1000") -> str:
    """
    Fast TCP sweep. Root-less CONNECT scan by default. JSON output for LLM.
    Returns pretty-printed text plus port-only summary the pipeline can reuse.
    """
    print(f"  [*] naabu -host {target} -top-ports {top_ports} -json")
    raw = run_tool(
        ["naabu", "-host", target, "-top-ports", top_ports, "-json", "-silent"],
        timeout=120,
    )
    ports: list[int] = []
    for line in raw.splitlines():
        try:
            ports.append(int(json.loads(line).get("port", 0)))
        except (ValueError, json.JSONDecodeError):
            continue
    ports = sorted(set(p for p in ports if p > 0))
    summary = f"[naabu] {len(ports)} open TCP ports on {target}: {','.join(map(str, ports)) or 'none'}"
    return summary + "\n\n[naabu raw JSON]\n" + raw


def _naabu_extract_ports(target: str, top_ports: str = "1000") -> list[int]:
    """Silent variant used internally by the two-stage pipeline."""
    raw = run_tool(
        ["naabu", "-host", target, "-top-ports", top_ports, "-json", "-silent"],
        timeout=120,
    )
    ports: set[int] = set()
    for line in raw.splitlines():
        try:
            p = int(json.loads(line).get("port", 0))
            if p > 0:
                ports.add(p)
        except (ValueError, json.JSONDecodeError):
            continue
    return sorted(ports)


def _naabu_extract_verified_ports(target: str, top_ports: str = "1000") -> tuple[list[int], list[int]]:
    """
    naabu sweep + TCP-handshake reconciliation. Returns (verified, filtered_false_positives).
    Prevents wasting nmap/nuclei time on ports naabu claimed but don't actually accept.
    """
    ports = _naabu_extract_ports(target, top_ports)
    verified: list[int] = []
    filtered: list[int] = []
    for p in ports:
        (verified if _tcp_verify(target, p) else filtered).append(p)
    return sorted(verified), sorted(filtered)


def run_nmap_targeted(target: str, ports: list[int]) -> str:
    """
    Deep nmap (-sV -sC) restricted to a pre-discovered port list.
    Used as stage 2 after naabu sweep.
    """
    if not ports:
        return "[nmap-targeted] naabu found no ports — skipping deep scan."
    port_arg = ",".join(map(str, ports))
    print(f"  [*] nmap -sV -sC -T3 -p {port_arg} {target}")
    return run_tool(
        ["nmap", "-sV", "-sC", "-T3", "-p", port_arg, target],
        timeout=600,
    )


def run_httpx(target: str) -> str:
    """
    ProjectDiscovery httpx (installed as `httpx-pd`). Replaces curl-headers.
    Returns tech-detect + title + status + server + IP + TLS in one call.
    """
    tgt = target if target.startswith(("http://", "https://")) else target
    print(f"  [*] httpx-pd -u {tgt} (title/tech/server/tls/status)")
    return run_tool(
        [
            "httpx-pd", "-u", tgt,
            "-title", "-tech-detect", "-server", "-status-code",
            "-tls-grab", "-ip", "-cname",
            "-json", "-silent", "-no-color",
        ],
        timeout=60,
    )


def run_nuclei(target: str, severity: str = "critical,high,medium,low") -> str:
    """
    Nuclei template scan. 8k+ community templates including CISA KEV.
    Default severity band tuned for CPTC (skip 'info' noise).
    """
    tgt = target if target.startswith(("http://", "https://")) else f"http://{target}"
    print(f"  [*] nuclei -u {tgt} -severity {severity} -jsonl (this can take 1-5 min)")
    return run_tool(
        [
            "nuclei", "-u", tgt,
            "-severity", severity,
            "-jsonl", "-silent", "-no-color",
            "-timeout", "10",
            "-rate-limit", "50",
        ],
        timeout=600,
    )


def run_nuclei_kev(target: str) -> str:
    """CISA Known-Exploited-Vulnerabilities only — highest-signal subset."""
    tgt = target if target.startswith(("http://", "https://")) else f"http://{target}"
    print(f"  [*] nuclei -u {tgt} -tags kev -jsonl (KEV subset — fast)")
    return run_tool(
        [
            "nuclei", "-u", tgt,
            "-tags", "kev",
            "-jsonl", "-silent", "-no-color",
            "-timeout", "10",
        ],
        timeout=300,
    )


# ─────────────────────────────────────────────
# PIPELINES
# ─────────────────────────────────────────────

def run_recon_pipeline(target: str) -> dict:
    """
    Ground-truth CPTC-flavored recon pipeline:
      1) naabu fast TCP sweep
      2) TCP-handshake reconciliation (drop naabu false positives)
      3) nmap -sV -sC on verified ports
      4) nmap UDP top-100 (SNMP/DNS/TFTP/IPMI/NetBIOS)
      5) TLS cert grab on every TLS-suspect port that verified
      6) SSH banner probe if port 22 verified (real SSH / tarpit / proxy)
      7) httpx + nuclei-kev if any web port verified
      8) dig + whois for asset context
    """
    print(f"\n[*] MEGATRON pipeline recon on {target}")
    print("─" * 60)
    results: dict[str, str] = {}

    verified, filtered = _naabu_extract_verified_ports(target, "1000")
    summary = (
        f"Verified open TCP ports ({len(verified)}): {','.join(map(str, verified)) or 'none'}\n"
        f"Naabu false positives filtered ({len(filtered)}): "
        f"{','.join(map(str, filtered)) or 'none'}"
    )
    results["naabu_summary"] = summary
    print(f"  [naabu-verify] {len(verified)} real, {len(filtered)} filtered "
          f"{'(' + ','.join(map(str, filtered)) + ')' if filtered else ''}")

    results["nmap_deep"] = run_nmap_targeted(target, verified)
    results["nmap_udp"]  = run_nmap_udp_top100(target)
    results["dig"]       = run_dig(target)
    results["whois"]     = run_whois(target)

    tls_hits = [p for p in verified if p in TLS_SUSPECT_PORTS]
    if tls_hits:
        results["tls_certs"] = "\n\n".join(run_tls_cert(target, p) for p in tls_hits)
    else:
        results["tls_certs"] = "[skipped] no TLS-suspect ports verified"

    if 22 in verified:
        results["ssh_probe"] = probe_ssh_banner(target, 22)
    else:
        results["ssh_probe"] = "[skipped] port 22 not in verified list"

    if any(p in WEB_SUSPECT_PORTS for p in verified):
        results["httpx"]        = run_httpx(target)
        results["nuclei_kev"]   = run_nuclei_kev(target)
        results["waf_detect"]   = detect_waf(target)
        results["katana"]       = run_katana(target)
        results["feroxbuster"]  = run_feroxbuster(target)
        results["dalfox"]       = run_dalfox(target)
    else:
        for k in ("httpx", "nuclei_kev", "waf_detect", "katana", "feroxbuster", "dalfox"):
            results[k] = "[skipped] no web port in verified list"

    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        results["subfinder"] = run_subfinder(target)
    else:
        results["subfinder"] = "[skipped] target is an IP, not a domain"

    if any(p in WEB_SUSPECT_PORTS for p in verified):
        api_spec = _find_openapi_spec(target)
        if api_spec:
            results["schemathesis"] = run_schemathesis(api_spec)
        else:
            results["schemathesis"] = "[skipped] no OpenAPI/Swagger spec auto-detected"
    else:
        results["schemathesis"] = "[skipped] no web port in verified list"

    print("─" * 60)
    print("[+] Pipeline recon complete.\n")
    return results


def _find_openapi_spec(target: str) -> str | None:
    """
    Auto-probe common OpenAPI/Swagger paths. Returns full URL if found.
    Enables Tier 3 API-aware chaining: if the app exposes /openapi.json,
    schemathesis auto-fuzzes it without user configuration.
    """
    base = _webify(target)
    candidates = [
        "/openapi.json", "/swagger.json", "/api-docs", "/v1/openapi.json",
        "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
        "/api/openapi.json", "/api/swagger.json", "/docs/openapi.json",
    ]
    for path in candidates:
        url = base.rstrip("/") + path
        out = run_tool(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "-A", "MEGATRON/2.2", "--max-time", "5", url],
            timeout=8,
        )
        if out.strip() == "200":
            print(f"  [openapi-autodetect] found spec at {url}")
            return url
    return None


def run_default_recon(target: str) -> dict:
    """Legacy 'run all except nikto' flow — kept for menu backwards compat."""
    print(f"\n[*] Starting classic recon on: {target}")
    print("─" * 50)
    results = {
        "nmap":         run_nmap(target),
        "whois":        run_whois(target),
        "whatweb":      run_whatweb(target),
        "curl_headers": run_curl_headers(target),
        "dig":          run_dig(target),
    }
    print("─" * 50)
    print("[+] Classic recon complete.\n")
    return results


# ─────────────────────────────────────────────
# SPECIALIST TOOLS (Tier 1 + Tier 2 — modern 2025-2026 stack)
# ─────────────────────────────────────────────

_FEROX_WORDLIST = "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
_SSRFMAP_PATH   = "/home/d3ath/SSRFmap/ssrfmap.py"


def _webify(target: str, scheme: str = "http") -> str:
    """Ensure target is a URL for tools that require it."""
    return target if target.startswith(("http://", "https://")) else f"{scheme}://{target}"


def run_katana(target: str) -> str:
    """Katana: JS-aware SPA crawler (ProjectDiscovery). Feeds URL discovery."""
    url = _webify(target)
    print(f"  [*] katana crawl {url} depth=2 (jsluice-like on JS)")
    return run_tool(
        ["katana", "-u", url, "-depth", "2", "-jc", "-jsonl", "-silent", "-no-color", "-timeout", "10"],
        timeout=300,
    )


def run_feroxbuster(target: str, wordlist: str = _FEROX_WORDLIST) -> str:
    """Recursive content discovery with automatic recursion. Fastest coverage-per-second."""
    url = _webify(target)
    if not run_tool(["test", "-f", wordlist], timeout=5).startswith("[!]"):
        pass
    print(f"  [*] feroxbuster {url} (depth 2, JSON out, rate-limited)")
    return run_tool(
        [
            "feroxbuster", "-u", url, "-w", wordlist,
            "--depth", "2", "--silent", "--json",
            "--rate-limit", "200", "--timeout", "10",
            "--extensions", "php,html,txt,js,bak,zip,tar.gz",
        ],
        timeout=600,
    )


def run_dalfox(target: str) -> str:
    """XSS scanner (reflected, DOM, stored, blind). JSON output, active — CPTC bread & butter."""
    url = _webify(target)
    print(f"  [*] dalfox url {url} --format json")
    return run_tool(
        ["dalfox", "url", url, "--format", "json", "--silence", "--no-color", "--worker", "50"],
        timeout=600,
    )


def run_sqlmap(target: str, level: int = 1, risk: int = 1) -> str:
    """
    sqlmap SOTA SQL injection. Non-destructive defaults (level=1, risk=1, --batch).
    Higher level/risk = more aggressive; competition-safe stays at 1/1.
    """
    url = _webify(target)
    print(f"  [*] sqlmap {url} --batch --level={level} --risk={risk}")
    return run_tool(
        [
            "sqlmap", "-u", url, "--batch",
            f"--level={level}", f"--risk={risk}",
            "--random-agent", "--timeout=15", "--retries=1",
            "--output-dir=/tmp/megatron-sqlmap",
        ],
        timeout=600,
    )


def run_commix(target: str) -> str:
    """Command injection scanner. Batch mode, safe defaults."""
    url = _webify(target)
    print(f"  [*] commix -u {url} --batch")
    return run_tool(
        ["commix", "-u", url, "--batch", "--random-agent", "--timeout=15"],
        timeout=600,
    )


def run_sstimap(target: str) -> str:
    """Server-Side Template Injection scanner (Jinja2/Twig/Freemarker/Velocity)."""
    url = _webify(target)
    print(f"  [*] sstimap -u {url}")
    return run_tool(
        ["sstimap", "-u", url, "--level", "1"],
        timeout=300,
    )


def run_ssrfmap(target: str) -> str:
    """
    SSRF exploitation. Requires a raw HTTP request file — for autonomy we send
    a generic GET-with-URL-param probe. For real exploitation the user should
    craft a request file manually.
    """
    url = _webify(target)
    req_path = "/tmp/megatron-ssrfmap-req.txt"
    from urllib.parse import urlparse
    host = urlparse(url).netloc
    with open(req_path, "w") as f:
        f.write(f"GET /?url=SSRF HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MEGATRON/2.2\r\n\r\n")
    print(f"  [*] ssrfmap probe against {url}")
    return run_tool(
        ["python3", _SSRFMAP_PATH, "-r", req_path, "-p", "url", "-m", "readfiles"],
        timeout=180,
    )


def run_crlfuzz(target: str) -> str:
    """CRLF injection / HTTP response splitting scanner."""
    url = _webify(target)
    print(f"  [*] crlfuzz -u {url}")
    return run_tool(
        ["crlfuzz", "-u", url, "-s"],
        timeout=180,
    )


def run_schemathesis(spec_url: str) -> str:
    """
    OpenAPI / Swagger fuzzer. spec_url must point to an OpenAPI JSON/YAML.
    Try common paths: /openapi.json, /swagger.json, /api-docs.
    """
    print(f"  [*] schemathesis run {spec_url} --checks=all")
    return run_tool(
        [
            "schemathesis", "run", spec_url,
            "--checks=all", "--hypothesis-max-examples=25",
            "--show-trace", "--no-color",
        ],
        timeout=600,
    )


def run_subfinder(domain: str) -> str:
    """Passive subdomain enumeration (30+ sources)."""
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    print(f"  [*] subfinder -d {domain} -all -silent")
    return run_tool(
        ["subfinder", "-d", domain, "-all", "-silent", "-json"],
        timeout=180,
    )


def run_trufflehog(target: str) -> str:
    """Secret detection. Accepts URL (git clone), local path, or filesystem prefix."""
    print(f"  [*] trufflehog on {target}")
    if target.startswith(("http://", "https://")) and target.endswith(".git"):
        cmd = ["trufflehog", "git", target, "--json", "--only-verified"]
    elif "/" in target and not target.startswith("http"):
        cmd = ["trufflehog", "filesystem", target, "--json", "--only-verified"]
    else:
        return "[trufflehog] skipped — target isn't a git URL or filesystem path"
    return run_tool(cmd, timeout=300)


def run_semgrep(path: str) -> str:
    """SAST via Semgrep. Only useful if target is a local source-code path."""
    print(f"  [*] semgrep --config=auto {path}")
    return run_tool(
        ["semgrep", "--config=auto", "--json", "--quiet", path],
        timeout=600,
    )


def run_gowitness(target: str) -> str:
    """Screenshot web target (requires chromium — optional Tier 3)."""
    url = _webify(target)
    outdir = "/tmp/megatron-gowitness"
    print(f"  [*] gowitness scan single --url {url}")
    return run_tool(
        ["gowitness", "scan", "single", "--url", url,
         "--screenshot-path", outdir, "--write-db"],
        timeout=120,
    )


def run_playwright_probe(target: str) -> str:
    """
    Tier 3 browser-driven probe: launches headless Chromium via Playwright, loads the
    target, extracts every <form>, every <input>, every <a href>, records HTTP requests
    made by JS, and captures a screenshot. This is the foundation for the Shannon-style
    "No Exploit, No Report" workflow — actual PoC execution builds on top of this.

    Returns human-readable summary. Requires `playwright install chromium` on host.
    Skips silently with a diagnostic if playwright isn't installed (kept optional).
    """
    url = _webify(target)
    print(f"  [*] playwright probe {url} (headless chromium, form+link+xhr extraction)")
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        return "[playwright-probe] SKIPPED — install with: pip install playwright && playwright install chromium"

    script = r"""
import json, sys
from playwright.sync_api import sync_playwright

url = sys.argv[1]
report = {"url": url, "forms": [], "inputs": [], "links": [], "xhr": [], "console": [], "title": None}

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 800})
    page = ctx.new_page()
    page.on("request",  lambda r: report["xhr"].append({"method": r.method, "url": r.url, "resource_type": r.resource_type}) if r.resource_type in ("xhr", "fetch") else None)
    page.on("console",  lambda m: report["console"].append({"type": m.type, "text": m.text[:200]}))
    try:
        page.goto(url, timeout=15000, wait_until="networkidle")
    except Exception as e:
        report["nav_error"] = str(e)[:200]
    report["title"] = page.title()
    for f in page.query_selector_all("form"):
        report["forms"].append({
            "action":  f.get_attribute("action") or "",
            "method":  (f.get_attribute("method") or "GET").upper(),
            "inputs":  [{"name": i.get_attribute("name"), "type": i.get_attribute("type") or "text"} for i in f.query_selector_all("input,textarea,select") if i.get_attribute("name")],
        })
    for inp in page.query_selector_all("input,textarea,select"):
        name = inp.get_attribute("name")
        if name:
            report["inputs"].append({"name": name, "type": inp.get_attribute("type") or "text"})
    for a in page.query_selector_all("a[href]")[:100]:
        report["links"].append(a.get_attribute("href"))
    page.screenshot(path="/tmp/megatron-playwright.png", full_page=True)
    browser.close()

print(json.dumps(report, indent=2))
"""
    return run_tool(["python3", "-c", script, url], timeout=45)


_WAF_SIGS: list[tuple[str, str]] = [
    ("cloudflare",       "cf-ray"),
    ("cloudflare",       "server: cloudflare"),
    ("aws waf",          "x-amzn-requestid"),
    ("aws waf",          "x-amz-cf-id"),
    ("akamai",           "akamai-ghost"),
    ("akamai",           "x-akamai-transformed"),
    ("imperva incapsula","x-iinfo"),
    ("imperva incapsula","incap_ses"),
    ("f5 big-ip",        "bigip"),
    ("f5 big-ip",        "x-wa-info"),
    ("sucuri",           "x-sucuri-id"),
    ("sucuri",           "server: sucuri"),
    ("modsecurity",      "mod_security"),
    ("modsecurity",      "server: mod_security"),
    ("wordfence",        "wordfence"),
    ("barracuda",        "barra_counter_session"),
    ("citrix netscaler", "ns_af"),
    ("fortiweb",         "fortiwafsid"),
]


def detect_waf(target: str) -> str:
    """
    Fingerprint WAF from HTTP response headers/cookies. Reads httpx JSON output
    if available, else does a fresh curl -sI. Returns human-readable summary.
    """
    print(f"  [*] waf-detect on {target}")
    url = _webify(target)
    raw = run_tool(
        ["curl", "-skI", "-A", "MEGATRON/2.2", "--max-time", "10", url],
        timeout=15,
    ).lower()
    hits: set[str] = set()
    for name, sig in _WAF_SIGS:
        if sig in raw:
            hits.add(name)
    if not hits:
        return f"[waf-detect] no known WAF signatures matched on {url}"
    return f"[waf-detect] WAF detected on {url}: {', '.join(sorted(hits))}"


# ─────────────────────────────────────────────
# MENU + FORMATTING
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1":  ("nmap (deep)",           run_nmap),
    "2":  ("whois",                 run_whois),
    "3":  ("whatweb",               run_whatweb),
    "4":  ("curl headers",          run_curl_headers),
    "5":  ("dig DNS",               run_dig),
    "6":  ("nikto (slow)",          run_nikto),
    "7":  ("naabu (fast TCP)",      run_naabu),
    "8":  ("httpx (web probe)",     run_httpx),
    "9":  ("nuclei-kev (CISA KEV)", run_nuclei_kev),
    "0":  ("nuclei (full)",         run_nuclei),
    "u":  ("nmap UDP top-100",      run_nmap_udp_top100),
    "t":  ("TLS cert (443)",        lambda tgt: run_tls_cert(tgt, 443)),
    "s":  ("SSH banner probe (22)", lambda tgt: probe_ssh_banner(tgt, 22)),
    "x":  ("dalfox (XSS)",          run_dalfox),
    "q":  ("sqlmap (SQLi)",         run_sqlmap),
    "k":  ("katana (JS crawler)",   run_katana),
    "f":  ("feroxbuster (dirbust)", run_feroxbuster),
    "c":  ("commix (cmd-inject)",   run_commix),
    "i":  ("sstimap (SSTI)",        run_sstimap),
    "r":  ("ssrfmap (SSRF)",        run_ssrfmap),
    "l":  ("crlfuzz (CRLF)",        run_crlfuzz),
    "e":  ("subfinder (subdomains)", run_subfinder),
    "h":  ("trufflehog (secrets)",  run_trufflehog),
    "g":  ("semgrep (SAST)",        run_semgrep),
    "w":  ("WAF detect",            detect_waf),
    "v":  ("gowitness screenshot",  run_gowitness),
    "y":  ("schemathesis (API fuzz)", run_schemathesis),
    "b":  ("playwright probe (Tier 3)", run_playwright_probe),
}


def format_recon_for_llm(results: dict) -> str:
    """Flatten dict of tool outputs into one string for the LLM."""
    chunks: list[str] = []
    for tool, data in results.items():
        chunks.append(f"\n{'='*50}\n[ {tool.upper()} OUTPUT ]\n{'='*50}\n{str(data).strip()}")
    return "\n".join(chunks)


def interactive_tool_run(target: str) -> str:
    """
    Menu-driven recon. Keeps legacy 'a' (classic all-except-nikto) and 'n' (add nikto);
    adds 'p' for the new 2-stage CPTC pipeline (naabu → nmap → httpx/nuclei-kev).
    """
    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name}")
    print("  [a] Classic recon (nmap/whois/whatweb/curl/dig)")
    print("  [n] Classic + nikto (slow)")
    print("  [p] MEGATRON pipeline: naabu→nmap+UDP+TLS+SSH+httpx+katana+feroxbuster+dalfox+nuclei-kev+waf+subfinder  (RECOMMENDED)")
    choice = input("\nChoice(s), e.g. '1 3 5' or 'p' or 'a': ").strip().lower()

    if choice == "a":
        return format_recon_for_llm(run_default_recon(target))
    if choice == "n":
        results = run_default_recon(target)
        results["nikto"] = run_nikto(target)
        return format_recon_for_llm(results)
    if choice == "p":
        return format_recon_for_llm(run_recon_pipeline(target))

    combined: dict[str, str] = {}
    for key in choice.split():
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = func(target)
        else:
            print(f"[!] Unknown option: {key}")
    return format_recon_for_llm(combined)


# ─────────────────────────────────────────────
# LLM TOOL DISPATCH (allowlist)
# ─────────────────────────────────────────────

ALLOWED_TOOLS = {
    "nmap", "whois", "whatweb", "curl", "dig", "nikto",
    "naabu", "httpx-pd", "nuclei",
    "dalfox", "sqlmap", "katana", "feroxbuster", "commix",
    "sstimap", "crlfuzz", "subfinder", "trufflehog",
    "schemathesis", "semgrep", "gowitness",
}


def run_tool_by_command(command_str: str) -> str:
    """Called by llm.py when the LLM emits [TOOL: <cmd>]. Allowlisted."""
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."
    tool = parts[0].lower().split("/")[-1]
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' is not permitted. Allowed: {sorted(ALLOWED_TOOLS)}"
    return run_tool(parts, timeout=300)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    tgt = input("Test target: ").strip() or "127.0.0.1"
    print(format_recon_for_llm(run_recon_pipeline(tgt)))
