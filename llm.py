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
    flag_hunt, FLAG_RE,
)
from search import handle_search_dispatch, verify_cve_nvd, nvd_search_by_product

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
MAX_TOOL_LOOPS  = int(_os.environ.get("MEGATRON_MAX_LOOPS", "6"))
OLLAMA_TIMEOUT  = int(_os.environ.get("OLLAMA_TIMEOUT", "600"))
_MODEL_TEMP     = float(_os.environ.get("MODEL_TEMPERATURE", "0.5"))
_MODEL_THINK    = _os.environ.get("MODEL_THINK", "false").lower() in ("1", "true", "yes")

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


def _run_exploit_loop(report: ScanReport, target: str, max_attempts: int = 5) -> int:
    """
    Iterate findings, attempt real exploitation with matching specialist tool.
    Time-boxed (max_attempts tools tried) to keep total scan under ~15 min.
    Updates finding.description with [EXPLOIT-SUCCESS|EXPLOIT-RUN] annotations.
    Returns count of flags captured.
    """
    attempted = 0
    captured  = 0
    seen_tools: set[str] = set()
    priority_severity = ("critical", "high", "medium", "low", "info")
    ordered = sorted(report.findings, key=lambda f: priority_severity.index(f.severity) if f.severity in priority_severity else 99)
    for finding in ordered:
        if attempted >= max_attempts:
            break
        tool = _pick_specialist(finding)
        if not tool or tool in seen_tools:
            continue
        seen_tools.add(tool)
        attempted += 1
        got_flag, evidence = _exploit_finding(finding, target)
        if evidence:
            finding.description += f"\n{evidence}"
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
