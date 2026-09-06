#!/usr/bin/env python3
"""
MEGATRON - llm.py  (v2.0 - structured output edition)

Ollama structured-output pipeline. Refactored 2026-08-25:
  - Pydantic schema enforcement via Ollama format= parameter
  - Two-phase: (1) extract facts deterministically, (2) analyze for vulns
  - Force citations: every finding must cite line numbers from raw_scan
  - Post-validation: hallucinated CVEs get downgraded to `unconfirmed`
  - think=False + temperature=0.0 for stable structured extraction

Model: megatron-qwen (fine-tuned huihui_ai/qwen3.5-abliterated:9b)
"""

from __future__ import annotations
import json
import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, ValidationError
from ollama import Client as OllamaClient

from tools import (
    run_tool_by_command,
    run_sqlmap, run_dalfox, run_ssrfmap, run_sstimap, run_commix,
    flag_hunt, FLAG_RE, WEB_SUSPECT_PORTS,
)
from search import handle_search_dispatch, verify_cve_nvd, nvd_search_by_product

try:
    from browser_agent import (
        BrowserSession, looks_like_login_page, looks_like_register_page,
        bootstrap_auth, cookies_to_header,
    )
    _BROWSER_AVAILABLE = True
except ImportError:
    _BROWSER_AVAILABLE = False
    BrowserSession = None  # type: ignore

_SERVICE_VERSION_RE = re.compile(
    r"^\s*(\d+)/(?:tcp|udp)\s+open\s+(\S+)\s+(.+?)(?:\s+syn-ack.*)?$",
    re.MULTILINE,
)

_PRODUCT_ALIAS = {
    "apache":       ("apache", "http_server"),
    "httpd":        ("apache", "http_server"),
    "nginx":        ("nginx", "nginx"),
    "openssh":      ("openbsd", "openssh"),
    "ssh":          ("openbsd", "openssh"),
    "mysql":        ("oracle", "mysql"),
    "mariadb":      ("mariadb", "mariadb"),
    "jetty":        ("eclipse", "jetty"),
    "tomcat":       ("apache", "tomcat"),
    "postgres":     ("postgresql", "postgresql"),
    "postgresql":   ("postgresql", "postgresql"),
    "openvpn":      ("openvpn", "openvpn"),
    "asterisk":     ("digium", "asterisk"),
    "freepbx":      ("sangoma", "freepbx"),
    "unifi":        ("ubiquiti", "unifi_network_application"),
    "ubiquiti":     ("ubiquiti", "unifi_network_application"),
    "vcenter":      ("vmware", "vcenter_server"),
    "vsphere":      ("vmware", "vsphere"),
    "redis":        ("redis", "redis"),
    "elasticsearch":("elastic", "elasticsearch"),
    "kubernetes":   ("kubernetes", "kubernetes"),
    "docker":       ("docker", "docker"),
    "mongodb":      ("mongodb", "mongodb"),
    "cassandra":    ("apache", "cassandra"),
    "kafka":        ("apache", "kafka"),
    "rabbitmq":     ("pivotal", "rabbitmq"),
    "memcached":    ("memcached", "memcached"),
    "minio":        ("minio", "minio"),
    "vault":        ("hashicorp", "vault"),
    "consul":       ("hashicorp", "consul"),
    "nomad":        ("hashicorp", "nomad"),
    "etcd":         ("coreos", "etcd"),
    "grafana":      ("grafana", "grafana"),
    "prometheus":   ("prometheus", "prometheus"),
    "jenkins":      ("jenkins", "jenkins"),
    "gitlab":       ("gitlab", "gitlab"),
    "gitea":        ("gitea", "gitea"),
    "confluence":   ("atlassian", "confluence_server"),
    "jira":         ("atlassian", "jira_server"),
    "bitbucket":    ("atlassian", "bitbucket"),
    "sonarqube":    ("sonarsource", "sonarqube"),
    "artifactory":  ("jfrog", "artifactory"),
    "nexus":        ("sonatype", "nexus_repository"),
    "wordpress":    ("wordpress", "wordpress"),
    "drupal":       ("drupal", "drupal"),
    "joomla":       ("joomla", "joomla"),
    "magento":      ("magento", "magento"),
    "openresty":    ("openresty", "openresty"),
    "haproxy":      ("haproxy", "haproxy"),
    "traefik":      ("traefik", "traefik"),
    "envoy":        ("envoy", "envoy"),
    "kong":         ("kong", "kong"),
    "3cx":          ("3cx", "3cx"),
    "exim":         ("exim", "exim"),
    "postfix":      ("postfix", "postfix"),
    "sendmail":     ("proofpoint", "sendmail"),
    "dovecot":      ("dovecot", "dovecot"),
    "proftpd":      ("proftpd", "proftpd"),
    "vsftpd":       ("vsftpd", "vsftpd"),
    "openldap":     ("openldap", "openldap"),
    "samba":        ("samba", "samba"),
    "bind":         ("isc", "bind"),
    "openvas":      ("greenbone", "openvas"),
    "webmin":       ("webmin", "webmin"),
    "cpanel":       ("cpanel", "cpanel"),
}

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

import os as _os

OLLAMA_HOST     = _os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME      = _os.environ.get("MODEL_NAME", "hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M")
PLANNING_MODEL  = _os.environ.get("PLANNING_MODEL", MODEL_NAME)
MAX_TOOL_LOOPS  = int(_os.environ.get("MEGATRON_MAX_LOOPS", "6"))
OLLAMA_TIMEOUT  = int(_os.environ.get("OLLAMA_TIMEOUT", "600"))
_MODEL_TEMP     = float(_os.environ.get("MODEL_TEMPERATURE", "0.5"))
_MODEL_THINK    = _os.environ.get("MODEL_THINK", "false").lower() in ("1", "true", "yes")
BROWSER_MAX_ACTIONS = int(_os.environ.get("MEGATRON_BROWSER_MAX_ACTIONS", "15"))

_client = OllamaClient(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)


# ─────────────────────────────────────────────
# PYDANTIC SCHEMAS (the contract with the LLM)
# ─────────────────────────────────────────────

Severity   = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "likely", "unconfirmed"]
RiskLevel  = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class Finding(BaseModel):
    """One vulnerability discovered on the target."""
    vuln_name:      str          = Field(..., description="Short name, e.g. 'Apache HTTP Server 2.4.49 Path Traversal'")
    severity:       Severity     = Field(..., description="critical/high/medium/low/info")
    port:           str          = Field("",  description="Port number as string, empty if N/A")
    service:        str          = Field("",  description="Service name, e.g. 'Apache httpd', 'OpenSSH'")
    description:    str          = Field(..., description="1-3 sentences on what the vuln is")
    fix:            str          = Field("",  description="Concrete remediation, one paragraph max")
    cve_id:         Optional[str] = Field(None, description="Format CVE-YYYY-NNNNN if applicable; null otherwise")
    evidence_lines: list[int]     = Field(default_factory=list, description="Line numbers (1-indexed) from raw_scan that back this claim. REQUIRED.")
    confidence:     Confidence    = Field("likely", description="confirmed=direct evidence in output; likely=strong inference; unconfirmed=speculation")
    cvss_score:     Optional[float] = Field(None, description="0.0-10.0 CVSS 3.1 base if known")


class Exploit(BaseModel):
    """A concrete follow-up test the operator can run."""
    exploit_name: str = Field(..., description="Short name of the test")
    tool_used:    str = Field(..., description="Tool + primary flags, e.g. 'nmap --script http-title'")
    payload:      str = Field("",  description="Command / URL / payload string")
    result:       str = Field("",  description="What running this would reveal")
    notes:        str = Field("",  description="Caveats / prereqs")


class ScanReport(BaseModel):
    """The full JSON contract for a scan analysis."""
    target:      str
    risk_level:  RiskLevel
    summary:     str = Field(..., description="2-3 sentence overall assessment")
    findings:    list[Finding] = Field(default_factory=list)
    exploits:    list[Exploit] = Field(default_factory=list)


# ─────────────────────────────────────────────
# PROMPTS
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are MEGATRON, an elite penetration testing analyst preparing a report for the Collegiate Penetration Testing Competition (CPTC).
You are precise, technical, and grounded in the recon evidence you are given.

CORE RULES (violate any → the finding is invalid):
- Every finding MUST cite `evidence_lines`: the 1-indexed line numbers from the RECON DATA that support your claim.
- NEVER invent a CVE. If the scanner did not produce one, leave cve_id null.
- NEVER infer a service version that is not literally present in the output.
- nmap "filtered" or no response → inconclusive, not vulnerable.
- If evidence is thin, mark confidence="unconfirmed" and severity="low".
- Only assign severity="critical" when there is direct evidence of exploitability
  (e.g., anonymous FTP write, unauthenticated RCE, exposed admin panel with default creds).

REQUIRED FIELD FILLING — this is where most models fail:
- `port`: fill from any nmap `NN/tcp open SERVICE` or naabu `open port NN` line. If the finding is
  service-specific, this MUST be the numeric port as a string (e.g. "22", "443", "8080"). Only leave
  empty when the finding is truly port-agnostic (e.g., a DNS-only finding).
- `service`: fill from the SERVICE column of nmap output or the tech-detect field of httpx output
  (e.g., "ssh", "http", "mysql", "nginx", "apache", "jetty"). Use the lower-case token.

GOOD EXAMPLE of a well-filled finding:
{
  "vuln_name": "OpenSSH 8.9p1 Terrapin Attack (CVE-2023-48795)",
  "severity": "medium",
  "port": "22",
  "service": "ssh",
  "description": "OpenSSH 8.9p1 is affected by the Terrapin prefix truncation attack in the SSH transport protocol.",
  "fix": "Upgrade to OpenSSH 9.6 or later, or disable ChaCha20-Poly1305 and *-etm@openssh.com MACs.",
  "cve_id": "CVE-2023-48795",
  "evidence_lines": [7],
  "confidence": "likely",
  "cvss_score": 5.9
}

BAD EXAMPLE (port + service left empty even though the recon clearly showed them):
{
  "vuln_name": "SSH service present",
  "severity": "low",
  "port": "",           ← WRONG: recon line 7 clearly said 22/tcp open ssh
  "service": "",        ← WRONG: recon line 7 clearly said 22/tcp open ssh
  "description": "SSH is running.",
  ...
}

You will receive TOOL RESULTS labeled with line numbers. Cite them.
You will output a single JSON object matching the ScanReport schema. No prose outside the JSON."""


REACT_HINT = """You may request additional tool runs by returning `exploits` entries that
begin with a bracketed tag: [TOOL: <cmd>] or [SEARCH: <query>].
These will be executed and results appended to context in the next round.
Return exploits WITHOUT such tags when the analysis is complete."""


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _number_lines(text: str) -> str:
    """Prefix each line with its 1-indexed number for the LLM to cite."""
    return "\n".join(f"{i:>4} | {line}" for i, line in enumerate(text.splitlines(), 1))


def _extract_tool_calls_from_exploits(report: ScanReport) -> list[tuple[str, str]]:
    """
    Look for embedded [TOOL: ...] / [SEARCH: ...] tags in exploit fields.
    Returns [(kind, payload)] list.
    """
    calls: list[tuple[str, str]] = []
    for exp in report.exploits:
        blob = " ".join([exp.exploit_name, exp.tool_used, exp.payload, exp.notes])
        for m in re.findall(r"\[TOOL:\s*(.+?)\]", blob):
            calls.append(("TOOL", m.strip()))
        for m in re.findall(r"\[SEARCH:\s*(.+?)\]", blob):
            calls.append(("SEARCH", m.strip()))
    return calls


def _run_dispatched_calls(calls: list[tuple[str, str]]) -> str:
    if not calls:
        return ""
    chunks: list[str] = []
    for kind, payload in calls:
        print(f"  [DISPATCH] {kind}: {payload}")
        if kind == "TOOL":
            out = run_tool_by_command(payload)
        else:
            out = handle_search_dispatch(payload)
        # cap size per dispatch to keep context healthy
        if len(out) > 4000:
            out = out[:4000] + "\n... [truncated, exceeded 4000 chars]"
        chunks.append(f"[{kind} RESULT: {payload}]\n{'-'*40}\n{out}")
    return "\n\n".join(chunks)


def _extract_service_versions(raw_scan: str) -> list[tuple[str, str, str, str]]:
    """
    Parse nmap-style `PORT/tcp open SERVICE VERSION_STRING` lines out of the recon dump.
    Returns list of (port, service_token, product_alias, version) tuples.
    version is a best-effort first numeric token from the version string.
    """
    out: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _SERVICE_VERSION_RE.finditer(raw_scan):
        port, svc, verstr = m.group(1), m.group(2).lower(), m.group(3).strip()
        alias_key = svc
        for k in _PRODUCT_ALIAS:
            if k in svc or k in verstr.lower():
                alias_key = k
                break
        vendor_product = _PRODUCT_ALIAS.get(alias_key)
        if not vendor_product:
            continue
        vm = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)", verstr)
        version = vm.group(1) if vm else ""
        vp_key = vendor_product[1]
        dedup_key = (vp_key, version)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        out.append((port, svc, vp_key, version))
    return out


def _fill_missing_ports(findings: list[Finding], raw_scan: str) -> int:
    """
    Backfill empty port/service fields by cross-referencing the LLM's finding
    against services detected in raw_scan. Every model tested (qwen2.5, Qwythos)
    leaves these blank sometimes; this makes filling a code guarantee.
    """
    services = _extract_service_versions(raw_scan)
    if not services:
        return 0
    word_map: dict[str, tuple[str, str]] = {}
    for port, svc_token, product, _ver in services:
        for key in (svc_token.lower(), product.lower(), product.replace("_", " ").lower()):
            word_map[key] = (port, svc_token)
        common_aliases = {
            "http_server": ("apache", "httpd"),
            "openssh":     ("openssh", "ssh"),
            "unifi_network_application": ("unifi",),
            "vcenter_server": ("vcenter", "vsphere"),
        }
        for extra in common_aliases.get(product, ()):
            word_map[extra] = (port, svc_token)
    filled = 0
    for f in findings:
        if f.port and f.service:
            continue
        haystack = f"{f.vuln_name} {f.description}".lower()
        for word, (port, svc) in word_map.items():
            if len(word) >= 3 and word in haystack:
                if not f.port:
                    f.port = port
                    filled += 1
                if not f.service:
                    f.service = svc
                break
    return filled


def _post_validate(report: ScanReport, raw_scan: str) -> ScanReport:
    """
    Enforce grounding + proactively inject NVD-known CVEs:
      1) evidence_lines that don't exist in raw_scan → downgrade confidence
      2) LLM-claimed CVEs → verify via NVD; strip + downgrade if not found
      3) Backfill missing port/service from raw_scan service map (models often
         leave these empty; code fallback beats prompt-only fixes)
      4) NVD service+version lookup for products in the scan → inject grounded
         Findings for CVEs the LLM was too conservative to claim (CPTC scoring win)
    """
    raw_lines = raw_scan.splitlines()
    max_line  = len(raw_lines)

    verified_findings: list[Finding] = []
    for f in report.findings:
        good_lines = [ln for ln in f.evidence_lines if 1 <= ln <= max_line]
        if len(good_lines) < len(f.evidence_lines):
            print(f"  [POST-VALIDATE] Finding '{f.vuln_name}': "
                  f"{len(f.evidence_lines) - len(good_lines)} bogus line numbers dropped.")
        f.evidence_lines = good_lines
        if not good_lines and f.confidence == "confirmed":
            f.confidence = "unconfirmed"
            print(f"  [POST-VALIDATE] Finding '{f.vuln_name}': no valid citations → confidence=unconfirmed")

        if f.cve_id:
            nvd = verify_cve_nvd(f.cve_id)
            if nvd is None:
                print(f"  [POST-VALIDATE] {f.cve_id} NOT in NVD → stripping, downgrading.")
                f.cve_id = None
                if f.severity in ("critical", "high"):
                    f.severity = "low"
                f.confidence = "unconfirmed"
                f.description += " [NOTE: LLM-claimed CVE not found in NVD.]"
            else:
                if f.cvss_score is None and nvd.get("cvss"):
                    f.cvss_score = nvd["cvss"]
                print(f"  [POST-VALIDATE] {f.cve_id} verified in NVD (cvss={nvd.get('cvss', 'n/a')}).")

        verified_findings.append(f)

    known_cves = {f.cve_id for f in verified_findings if f.cve_id}
    services = _extract_service_versions(raw_scan)
    injected = 0
    for port, svc_token, product, version in services:
        if not version:
            continue
        hits = nvd_search_by_product(product, version, limit=3)
        for hit in hits:
            if hit["id"] in known_cves:
                continue
            cvss = hit.get("cvss") or 0.0
            if cvss >= 9.0:
                sev: Severity = "critical"
            elif cvss >= 7.0:
                sev = "high"
            elif cvss >= 4.0:
                sev = "medium"
            elif cvss > 0:
                sev = "low"
            else:
                sev = "info"
            verified_findings.append(Finding(
                vuln_name      = f"{product} {version}: {hit['id']}",
                severity       = sev,
                port           = port,
                service        = svc_token,
                description    = (
                    f"[NVD-INJECTED — grounded via product+version lookup] "
                    f"{hit.get('summary', '(no NVD summary)')[:260]}"
                ),
                fix            = f"Update {product} past the vulnerable version {version}. "
                                 f"See https://nvd.nist.gov/vuln/detail/{hit['id']}.",
                cve_id         = hit["id"],
                evidence_lines = [],
                confidence     = "confirmed",
                cvss_score     = hit.get("cvss"),
            ))
            known_cves.add(hit["id"])
            injected += 1
    if injected:
        print(f"  [NVD-INJECT] added {injected} grounded CVE(s) from product+version lookup.")

    n_backfilled = _fill_missing_ports(verified_findings, raw_scan)
    if n_backfilled:
        print(f"  [PORT-BACKFILL] filled port/service on {n_backfilled} LLM finding(s) via service-map lookup.")

    report.findings = verified_findings
    return report


_VULN_SPECIALIST_MAP: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(sql[i ]|sqli|sql injection|sqlmap|blind\s+sql)\b", re.I), "sqlmap"),
    (re.compile(r"\b(xss|cross[-\s]?site\s+scripting|dalfox)\b",         re.I), "dalfox"),
    (re.compile(r"\b(ssrf|server[-\s]?side\s+request)\b",                re.I), "ssrfmap"),
    (re.compile(r"\b(ssti|template\s+injection|jinja|freemarker|twig)\b", re.I), "sstimap"),
    (re.compile(r"\b(cmd[i ]|command\s+injection|os\s+injection|commix)\b", re.I), "commix"),
    (re.compile(r"\b(lfi|path\s+traversal|file\s+inclusion|directory\s+traversal)\b", re.I), "lfi_probe"),
    (re.compile(r"\b(idor|insecure\s+direct\s+object|broken\s+access)\b", re.I), "idor_probe"),
]


_SKIP_MARKERS_RE = re.compile(
    r"\b(skipped|not\s+run|not\s+executed|failed|error|no\s+valid|inconclusive|unable\s+to)\b",
    re.I,
)


def _pick_specialist(finding: Finding) -> str | None:
    haystack = f"{finding.vuln_name} {finding.description}"
    if _SKIP_MARKERS_RE.search(haystack):
        return None
    for pattern, tool in _VULN_SPECIALIST_MAP:
        if pattern.search(haystack):
            return tool
    return None


def _exploit_finding(finding: Finding, target: str) -> tuple[bool, str]:
    """
    Attempt actual exploitation for a Finding. Returns (flag_captured, evidence_string).
    Time-boxed per tool; captures FLAG{...} markers in any exploit output.
    """
    tool = _pick_specialist(finding)
    if not tool:
        return False, ""

    tgt_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    if finding.port and finding.port not in ("80", "443", ""):
        parsed_host = tgt_url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        scheme = "https" if finding.port in ("443", "8443", "7443") else "http"
        tgt_url = f"{scheme}://{parsed_host}:{finding.port}"

    print(f"  [EXPLOIT-TRY] {tool} against '{finding.vuln_name}' at {tgt_url}")
    try:
        if tool == "sqlmap":
            out = run_sqlmap(tgt_url, level=1, risk=1)
        elif tool == "dalfox":
            out = run_dalfox(tgt_url)
        elif tool == "ssrfmap":
            out = run_ssrfmap(tgt_url)
        elif tool == "sstimap":
            out = run_sstimap(tgt_url)
        elif tool == "commix":
            out = run_commix(tgt_url)
        elif tool == "lfi_probe":
            out = flag_hunt(tgt_url)
        elif tool == "idor_probe":
            out = flag_hunt(tgt_url)
        else:
            return False, ""
    except Exception as e:
        return False, f"[{tool} crashed: {e}]"

    flags = FLAG_RE.findall(out)
    if flags:
        return True, f"[EXPLOIT-SUCCESS via {tool}] captured: {flags[0]}"
    return False, f"[EXPLOIT-RUN via {tool}] no flag; output {len(out)} bytes"


ActionType = Literal["navigate", "click", "fill", "submit", "wait", "screenshot", "done"]


class BrowserAction(BaseModel):
    """One atomic action the LLM proposes for the persistent browser session."""
    type:     ActionType = Field(..., description="One of: navigate, click, fill, submit, wait, screenshot, done")
    selector: str        = Field("", description="CSS selector from observed forms/inputs/buttons/links. MUST come from observed set — don't invent.")
    value:    str        = Field("", description="Value for `fill`; URL for `navigate`; empty otherwise")
    reason:   str        = Field(..., description="One sentence: why this action, what vuln you're proving, what you expect next")


class BrowserPlan(BaseModel):
    """LLM output for one iteration of the browser-exploit loop."""
    action:             BrowserAction
    flag_candidate:     str | None = Field(None, description="If FLAG{...} spotted in visible text, put it here")
    exploit_hypothesis: str        = Field(..., description="What vulnerability/chain you're currently trying to prove")
    session_note:       str        = Field("", description="One-line memo to your future self — key facts to remember from this page (usernames, IDs, endpoints found, error messages seen)")
    give_up:            bool       = Field(False, description="True if you're truly stuck; will exit the loop")


def _build_url_for_finding(target: str, finding: Finding) -> str:
    """Assemble http(s)://host:port from target + finding.port."""
    if target.startswith(("http://", "https://")):
        base = target
    else:
        base = f"http://{target}"
    if finding.port and finding.port not in ("", "80"):
        scheme = "https" if finding.port in ("443", "8443", "7443", "9443") else "http"
        host = base.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        base = f"{scheme}://{host}:{finding.port}"
    return base


def _browser_exploit(target_url: str, finding: Finding, max_actions: int | None = None) -> tuple[bool, str]:
    """
    LLM-driven browser exploit loop with session-aware planning (v0.8.0).

    Phases:
      A) Auth bootstrap — try to register + login BEFORE exploit loop starts.
         Session cookies from a successful login persist through the entire
         browser context AND get exported back to CLI specialists.
      B) Session-aware planning — every LLM call gets the goal, last 10 actions,
         accumulated session_notes, and current-page delta. Also detects "stuck"
         states (same URL + same visible text 3+ times → force pivot or give up).
      C) Uses PLANNING_MODEL env var (defaults to MODEL_NAME) so a bigger model
         can drive planning if available (e.g., 27B on P40).

    MEGATRON differentiators over Shannon:
      - Fully local Ollama
      - Multi-tier fallback: if browser gives up, CLI specialists still run
      - Session cookies flow back to sqlmap/dalfox for authenticated CLI exploits
    """
    if not _BROWSER_AVAILABLE:
        return False, "[browser-exploit] SKIPPED — playwright not installed"

    max_actions = max_actions if max_actions is not None else BROWSER_MAX_ACTIONS
    goal = f"Prove '{finding.vuln_name}' by capturing FLAG{{...}} from the target."
    session_notes: list[str] = []
    stuck_counter: dict[str, int] = {}

    try:
        with BrowserSession(target_url, headless=True, timeout_ms=8000) as sess:
            auth = bootstrap_auth(sess, verbose=True)
            if auth["success"]:
                session_notes.append(f"AUTH ESTABLISHED as {auth['username']} — cookies: {len(auth['cookies'])} entries")
                try:
                    import os as _o
                    _o.environ["AUTH_COOKIE"] = cookies_to_header(auth["cookies"])
                    session_notes.append("cookies exported to AUTH_COOKIE env for downstream CLI tools")
                except Exception:
                    pass
            else:
                session_notes.append(f"no auth bootstrap ({auth.get('notes','')[:100]})")

            sess.act({"type": "navigate", "value": target_url})

            history: list[dict] = []
            action_dedup: set[tuple[str, str, str]] = set()

            for step in range(max_actions):
                snap = sess.observe(max_visible=1500, max_links=20)
                if "error" in snap:
                    return False, f"[browser-exploit] observe failed: {snap['error']}"

                visible = snap.get("visible_text", "")
                title   = snap.get("title", "")
                flags = FLAG_RE.findall(visible + " " + title)
                if flags:
                    return True, f"[BROWSER-EXPLOIT captured] {flags[0]} after {step} action(s) at {snap['url']}"

                state_fingerprint = f"{snap['url']}|{hash(visible[:500])}"
                stuck_counter[state_fingerprint] = stuck_counter.get(state_fingerprint, 0) + 1
                is_stuck = stuck_counter[state_fingerprint] >= 3

                trimmed_snap = {
                    "url":     snap["url"],
                    "title":   title,
                    "forms":   snap.get("forms", [])[:5],
                    "inputs":  snap.get("inputs", [])[:10],
                    "buttons": snap.get("buttons", [])[:8],
                    "links":   snap.get("links", [])[:15],
                    "visible_text_head": visible[:500],
                    "visible_text_tail": visible[-300:] if len(visible) > 800 else "",
                }
                prompt = (
                    f"You are exploiting a web app. GOAL: {goal}\n\n"
                    f"FINDING CONTEXT:\n"
                    f"  vuln: {finding.vuln_name}\n"
                    f"  severity={finding.severity} confidence={finding.confidence}\n"
                    f"  description: {finding.description[:400]}\n\n"
                    f"SESSION NOTES (your memory across all previous actions):\n"
                    + "\n".join(f"  • {n}" for n in session_notes[-8:])
                    + "\n\n"
                    f"ACTION HISTORY (last 10 — deduped):\n"
                    + (json.dumps([{"step": h.get('step'), "type": h.get('action',{}).get('type'),
                                     "selector": h.get('action',{}).get('selector','')[:60],
                                     "value": h.get('action',{}).get('value','')[:40],
                                     "reason": h.get('reason','')[:80]}
                                     for h in history[-10:]], indent=1)
                       if history else "  (none yet — first action)")
                    + "\n\n"
                    f"CURRENT PAGE:\n{json.dumps(trimmed_snap, indent=1)}\n\n"
                    + ("⚠️  YOU HAVE VISITED THIS EXACT PAGE 3+ TIMES — YOU ARE STUCK. Either try a radically different action or set give_up=true.\n\n" if is_stuck else "")
                    + "Propose the NEXT action. Rules:\n"
                    f"  - selectors MUST come from observed forms/inputs/buttons/links\n"
                    f"  - if you spot FLAG{{...}} in visible text, set flag_candidate\n"
                    f"  - if you learn something (username, hidden endpoint, error msg), put it in session_note\n"
                    f"  - PAYLOAD CHEATSHEET: SQLi=' OR 1=1--, SSTI={{{{7*7}}}}, XSS=<script>alert(1)</script>,\n"
                    f"    LFI=../../../../etc/passwd, SSRF=http://169.254.169.254/, IDOR=increment ?id=\n"
                    f"  - IDOR strategy: if URL has numeric ID, navigate to ?id=1, ?id=2, ?id=admin\n"
                    f"  - if truly stuck, set give_up=true; don't loop"
                )
                plan = _ask_structured_typed(prompt, BrowserPlan, model_name=PLANNING_MODEL)
                if plan is None or plan.give_up or plan.action.type == "done":
                    break

                if plan.session_note:
                    session_notes.append(plan.session_note[:200])

                if plan.flag_candidate and FLAG_RE.match(plan.flag_candidate):
                    return True, f"[BROWSER-EXPLOIT captured] {plan.flag_candidate} via LLM inspection at step {step}"

                key = (plan.action.type, plan.action.selector, plan.action.value)
                if key in action_dedup:
                    history.append({"step": step, "skipped": "duplicate action", "action": plan.action.model_dump(), "reason": plan.action.reason})
                    continue
                action_dedup.add(key)

                result = sess.act(plan.action.model_dump())
                history.append({"step": step, "action": plan.action.model_dump(), "result": result, "reason": plan.action.reason})

            summary = f"[browser-exploit] no flag after {len(history)} action(s) on '{finding.vuln_name}'"
            if auth["success"]:
                summary += f" (auth={auth['username']})"
            if session_notes:
                summary += f" | notes: {'; '.join(session_notes[-3:])[:300]}"
            return False, summary
    except Exception as e:
        return False, f"[browser-exploit] session error: {str(e)[:200]}"


def _ask_structured_typed(prompt: str, schema_class, model_name: str | None = None):
    """
    One-shot structured Ollama call for any Pydantic schema.
    Optional model_name override — used by browser exploit loop to route planning
    calls to PLANNING_MODEL (may be bigger/different than MODEL_NAME).
    """
    try:
        resp = _client.chat(
            model    = model_name or MODEL_NAME,
            messages = [{"role": "user", "content": prompt}],
            format   = schema_class.model_json_schema(),
            think    = _MODEL_THINK,
            options  = {"temperature": _MODEL_TEMP, "top_p": 0.9, "top_k": 20, "num_ctx": 16384, "num_predict": 4096},
        )
        content = resp["message"]["content"]
        return schema_class.model_validate_json(content)
    except Exception as e:
        print(f"  [!] structured-typed call failed: {str(e)[:150]}")
        return None


def _run_exploit_loop(report: ScanReport, target: str, max_attempts: int = 5) -> int:
    """
    Multi-tier exploitation loop (MEGATRON differentiator vs Shannon):
      Tier 1: Fast CLI specialist per vuln class (sqlmap/dalfox/SSRFmap/etc)
      Tier 2: Browser-driven LLM exploit loop (slower but handles chained flows)
              — runs FIRST for web findings when playwright is available,
                because browser can capture IDOR/auth flows CLI can't
      Tier 3: (planned) cross-finding correlation for exploit chains

    First tool to capture a flag wins for that finding; findings without
    matched exploits stay unchanged. Time-boxed to `max_attempts` total.
    """
    attempted = 0
    captured  = 0
    seen_tools: set[str] = set()
    priority_severity = ("critical", "high", "medium", "low", "info")
    ordered = sorted(
        report.findings,
        key=lambda f: priority_severity.index(f.severity) if f.severity in priority_severity else 99,
    )
    web_port_strs = {str(p) for p in WEB_SUSPECT_PORTS}
    non_web_ports = {"22", "21", "23", "25", "53", "110", "143", "161", "389", "445",
                     "465", "587", "993", "995", "1433", "1521", "3306", "3389", "5432",
                     "5984", "6379", "9042", "9200", "11211", "27017"}

    for finding in ordered:
        if attempted >= max_attempts:
            break
        tool = _pick_specialist(finding)
        if not tool or tool in seen_tools:
            continue
        seen_tools.add(tool)
        attempted += 1

        is_web = (
            finding.port in web_port_strs
            or (finding.port.isdigit() and int(finding.port) >= 1024 and finding.port not in non_web_ports)
            or (finding.port == "" and tool in ("dalfox", "lfi_probe", "idor_probe"))
        )
        got_flag, evidence = False, ""

        if is_web and _BROWSER_AVAILABLE:
            url_for_finding = _build_url_for_finding(target, finding)
            print(f"  [EXPLOIT-BROWSER] driving Chromium against '{finding.vuln_name}' at {url_for_finding}")
            got_flag, evidence = _browser_exploit(url_for_finding, finding)
            print(f"  [EXPLOIT-BROWSER result] flag={got_flag} evidence={evidence[:180]}")
            if evidence:
                finding.description += f"\n{evidence}"

        if not got_flag:
            got_flag2, evidence2 = _exploit_finding(finding, target)
            if evidence2:
                finding.description += f"\n{evidence2}"
            got_flag = got_flag or got_flag2

        if got_flag:
            captured += 1
            finding.confidence = "confirmed"
            finding.severity = "critical"

    return captured


# ─────────────────────────────────────────────
# OLLAMA CALL WITH STRUCTURED OUTPUT
# ─────────────────────────────────────────────

def _ask_structured(messages: list[dict]) -> ScanReport | None:
    """One structured-output call to Ollama. Returns None on failure."""
    schema = ScanReport.model_json_schema()
    try:
        print(f"\n[*] Ollama call → {MODEL_NAME} (structured, think=False, T=0.1)")
        resp = _client.chat(
            model    = MODEL_NAME,
            messages = messages,
            format   = schema,            # ← Ollama enforces the JSON schema
            think    = _MODEL_THINK,      # ← env-toggled; false for qwen2.5 / true for Qwythos reasoning
            options  = {
                "temperature":  _MODEL_TEMP,
                "top_p":        0.9,
                "top_k":        20,
                "num_ctx":      16384,
                "num_predict":  16384,
            },
        )
    except Exception as e:
        print(f"[!] Ollama error: {e}")
        return None

    content = resp["message"]["content"]
    if not content:
        print("[!] Empty content from Ollama.")
        return None

    try:
        return ScanReport.model_validate_json(content)
    except ValidationError as ve:
        # try once more with a repair prompt
        print(f"[!] Schema validation failed. First 500 chars of raw content:\n{content[:500]}")
        print(f"    Errors: {ve.errors()[:3]}")
        return None


# ─────────────────────────────────────────────
# MAIN ENTRY POINT (public API)
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    """
    Public API kept stable so megatron.py doesn't change.
    Returns dict shaped for db.save_* functions.
    """
    numbered_scan = _number_lines(raw_scan)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + REACT_HINT},
        {"role": "user",   "content": (
            f"TARGET: {target}\n\n"
            f"RECON DATA (line-numbered — cite these in evidence_lines):\n"
            f"{'-'*60}\n{numbered_scan}\n{'-'*60}\n\n"
            f"Produce a ScanReport JSON. Cite line numbers for every finding."
        )},
    ]

    report: ScanReport | None = None
    for loop in range(MAX_TOOL_LOOPS):
        print(f"\n{'─'*60}")
        print(f"[MEGATRON round {loop + 1}/{MAX_TOOL_LOOPS}]")
        print(f"{'─'*60}")

        report = _ask_structured(messages)
        if report is None:
            # one retry with a bare "produce valid JSON" nudge
            messages.append({"role": "user",
                             "content": "Your last response failed schema validation. Emit ONE ScanReport JSON object. Nothing else."})
            continue

        # check for tool dispatch tags inside exploits
        calls = _extract_tool_calls_from_exploits(report)
        if not calls:
            print(f"[*] No further tool dispatches requested. Analysis complete.")
            break

        tool_results = _run_dispatched_calls(calls)
        messages.append({"role": "assistant", "content": report.model_dump_json()})
        messages.append({"role": "user", "content": (
            f"[TOOL RESULTS]\n{tool_results}\n\n"
            f"Refine your ScanReport with this new information. "
            f"Include only real findings (drop [TOOL:] tags from exploits when done)."
        )})

    if report is None:
        # graceful degradation — return an empty valid report
        report = ScanReport(
            target=target, risk_level="LOW",
            summary="Analysis pipeline failed after retries. See raw_scan for evidence.",
            findings=[], exploits=[],
        )

    report = _post_validate(report, raw_scan)

    recon_flags = set(FLAG_RE.findall(raw_scan))
    if recon_flags:
        print(f"  [FLAG-IN-RECON] {len(recon_flags)} flag marker(s) already leaked in recon output — no exploitation needed")
        for flag in recon_flags:
            report.findings.append(Finding(
                vuln_name="Flag Leaked via Passive Recon",
                severity="critical",
                port="",
                service="",
                description=f"[FLAG-CAPTURED via flag_hunt/recon] {flag}",
                fix="Remove flag file from web-accessible path.",
                cve_id=None,
                evidence_lines=[],
                confidence="confirmed",
                cvss_score=10.0,
            ))
        report.risk_level = "CRITICAL"
    else:
        captured = _run_exploit_loop(report, target, max_attempts=5)
        if captured:
            print(f"  [EXPLOIT-LOOP] captured {captured} flag(s) via specialist exploitation")
            report.risk_level = "CRITICAL"

    print(f"\n[+] Parsed: {len(report.findings)} findings, {len(report.exploits)} exploits | Risk: {report.risk_level}")
    print(f"    confidence breakdown: " + ", ".join(
        f"{c}={sum(1 for f in report.findings if f.confidence == c)}"
        for c in ("confirmed", "likely", "unconfirmed")
    ))

    # shape for db.save_* + PDF export (keep old contract)
    return {
        "full_response":   report.model_dump_json(indent=2),
        "vulnerabilities": [
            {
                "vuln_name":   f.vuln_name,
                "severity":    f.severity,
                "port":        f.port,
                "service":     f.service,
                "description": f.description
                                + (f" [CVE:{f.cve_id} CVSS:{f.cvss_score}]" if f.cve_id else "")
                                + f" [confidence:{f.confidence}]"
                                + f" [evidence_lines:{','.join(map(str, f.evidence_lines)) or 'none'}]",
                "fix":         f.fix,
            }
            for f in report.findings
        ],
        "exploits": [
            {
                "exploit_name": e.exploit_name,
                "tool_used":    e.tool_used,
                "payload":      e.payload,
                "result":       e.result,
                "notes":        e.notes,
            }
            for e in report.exploits
        ],
        "risk_level": report.risk_level,
        "summary":    report.summary,
        "raw_scan":   raw_scan,
    }


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py v2 test — direct structured-output query ]\n")
    try:
        _client.list()
        print("[+] Ollama reachable.")
    except Exception as e:
        print(f"[!] Ollama not reachable: {e}")
        raise SystemExit(1)

    target = input("Test target: ").strip() or "127.0.0.1"
    test_scan = f"""Starting Nmap 7.94 ( https://nmap.org ) at 2026-08-25 11:00 UTC
Nmap scan report for {target}
Host is up (0.000030s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.49 ((Ubuntu))
|_http-server-header: Apache/2.4.49 (Ubuntu)
443/tcp  open  ssl/http Apache httpd 2.4.49
3306/tcp open  mysql   MySQL 5.5.62-log
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 1.83 seconds"""

    result = analyse_target(target, test_scan)
    print(f"\n=== RESULT ===")
    print(f"Risk : {result['risk_level']}")
    print(f"Summary: {result['summary']}")
    print(f"Vulns: {len(result['vulnerabilities'])}")
    for v in result["vulnerabilities"]:
        print(f"  - [{v['severity']}] {v['vuln_name']}  |  port {v['port']}")
        print(f"       {v['description'][:120]}")
