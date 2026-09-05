# 🤖 MEGATRON

**AI-driven autonomous penetration testing framework for CPTC-style engagements.**

Ollama-local, structured-output LLM analysis, NVD-grounded CVEs, 20+ specialist recon tools chained into a single pipeline.

Built on top of [sooryathejas/METATRON](https://github.com/sooryathejas/METATRON) — substantially rewritten (structured output, ground-truth probes, proactive CVE injection, modern 2025-2026 tool stack).

---

## What makes it different

| Failure mode of most AI pentesters | How MEGATRON handles it |
|---|---|
| LLM hallucinates CVEs → false findings in the report | Every LLM-claimed CVE is verified against the NIST NVD API; unverified CVEs are stripped and severity downgraded |
| LLM is too conservative → misses obvious KEV CVEs (e.g., Apache 2.4.49) | Proactive product+version → NVD lookup **injects** grounded CVEs the LLM missed |
| Regex-parsing free-text LLM output breaks on the first bold markdown | Pydantic + Ollama `format=` JSON schema — zero regex, deterministic output |
| Naabu SYN-scan false positives waste minutes of nmap deep-scanning | Every naabu-claimed port is verified via raw TCP handshake before nmap runs |
| Port 22 open → assumed to be SSH, missed tarpits/honeypots | Dedicated banner classifier: `REAL_SSH` / `TARPIT_SUSPECT` / `EMPTY_ACCEPT` / `NON_SSH_DATA` |
| No OpenAPI awareness | Auto-probes 10 known Swagger/OpenAPI paths → chains `schemathesis` if found |
| No WAF awareness | Fingerprints 18 WAF signatures from response headers |

---

## The stack

**Ground-truth probes** (in-house)
Naabu-verify (TCP handshake reconciliation) · TLS cert grabber (openssl s_client, SNI-aware) · SSH banner classifier · WAF fingerprint · OpenAPI auto-detect

**Recon** (2020-era classics, still useful)
`nmap` · `whois` · `whatweb` · `curl` · `dig` · `nikto`

**Recon** (2024-2026 modern)
`naabu` · `httpx-pd` · `nuclei` (13,619 templates) · `katana` (JS-aware SPA crawler) · `feroxbuster` (recursive content discovery) · `subfinder` (30+ passive sources)

**Vulnerability specialists** (2025-2026 best-in-class)
`dalfox` (XSS) · `sqlmap` (SQLi) · `commix` (cmd injection) · `sstimap` (SSTI) · `SSRFmap` (SSRF) · `crlfuzz` (CRLF) · `schemathesis` (OpenAPI fuzz) · `trufflehog` (secrets) · `semgrep` (SAST)

**Post-scan** (optional)
`gowitness` (screenshots) · `testssl.sh` (deep TLS audit) · MariaDB persistence · ReportLab PDF/HTML export

**LLM**
Ollama (default `qwen2.5:7b-instruct` on 8GB VRAM — ~35 tok/s; scales to 27B on 24GB VRAM). Pluggable via `MODEL_NAME` in `llm.py`. `think=False` + `temperature=0.1` for deterministic structured extraction.

---

## Pipeline flow (the `[p]` menu option)

```
naabu -top-ports 1000
  ↓  filter false positives via raw TCP handshake
nmap -sV -sC (verified ports only)
  ↓
nmap -sU --top-ports 100  (UDP: SNMP/DNS/TFTP/IPMI/NetBIOS)
  ↓
openssl s_client → x509  (every TLS-suspect port)
  ↓
ssh-banner classifier    (port 22 if verified)
  ↓
whois + dig
  ↓  if any web port verified:
httpx-pd (tech/title/server/TLS/IP/CNAME)
  ↓
nuclei -tags kev  (CISA Known-Exploited-Vulnerabilities)
  ↓
WAF fingerprint  (18 vendor signatures)
  ↓
katana crawl -depth 2 -jc  (JS-aware)
  ↓
feroxbuster (recursive, SecLists raft-medium wordlist)
  ↓
dalfox url --format json  (XSS on discovered URLs)
  ↓  if OpenAPI/Swagger spec auto-detected:
schemathesis run --checks=all
  ↓  if target is a domain (not IP):
subfinder -d TARGET -all -silent
  ↓
Ollama structured analysis (Pydantic ScanReport schema)
  ↓
Post-validation:
  1. Cited evidence_lines exist in raw_scan?  → downgrade if not
  2. LLM-claimed CVE verified in NVD?         → strip + downgrade if not
  3. Detected services → NVD product+version  → INJECT grounded CVEs
  ↓
MariaDB save (5 tables: history / vulnerabilities / fixes / exploits_attempted / summary)
  ↓
Optional PDF / HTML export via ReportLab
```

---

## Install (Ubuntu 24.04 / Parrot OS)

Full step-by-step is in [docs/INSTALL.md](docs/INSTALL.md). Quick summary:

```bash
git clone git@github.com:d3ath69/Megatron.git ~/Megatron
cd ~/Megatron
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt sstimap schemathesis semgrep sqlmap

# System recon tools (universe repo on Ubuntu 24.04)
sudo add-apt-repository -y universe && sudo apt update
sudo apt install -y nmap whois whatweb curl dnsutils nikto mariadb-server unzip openssl

# SecLists (~2.5GB of wordlists)
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists

# ProjectDiscovery binaries (naabu / httpx-pd / nuclei / subfinder / katana)
# Modern specialists (dalfox / feroxbuster / trufflehog / crlfuzz / gowitness)
# commix (needs python→python3 shebang fix)
# SSRFmap (git clone, no pip)
#
# See docs/INSTALL.md for the full copy-paste block.

# Ollama + model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b-instruct

# MariaDB schema (creates megatron DB + user + 5 tables)
sudo mariadb < docs/schema.sql
```

**GPU note:** `qwen2.5:7b-instruct` fits comfortably in 8GB VRAM. For the 27B model (`hf.co/OBLITERATUS/Qwen3.8-27B-OBLITERATED:Q4_K_M`) you need 24GB+. Ollama auto-detects; add `OLLAMA_SCHED_SPREAD=true` to spread across multiple GPUs.

---

## Usage

```bash
cd ~/Megatron && source venv/bin/activate && python megatron.py
```

Menu → `[1] New Scan` → target IP or domain → `[p] MEGATRON pipeline (RECOMMENDED)`.

Individual specialist scans available via single-letter keys:
- `[x]` dalfox XSS · `[q]` sqlmap SQLi · `[k]` katana crawl · `[f]` feroxbuster dirbust
- `[c]` commix cmd injection · `[i]` sstimap SSTI · `[r]` ssrfmap SSRF · `[l]` crlfuzz
- `[e]` subfinder subdomains · `[h]` trufflehog secrets · `[g]` semgrep SAST
- `[w]` WAF detect · `[v]` gowitness screenshot · `[y]` schemathesis API fuzz
- `[t]` TLS cert grab · `[s]` SSH banner probe

Chain multiple: `1 8 9 t s` runs nmap + httpx + nuclei-kev + TLS cert + SSH probe.

---

## Roadmap

- [ ] **Browser automation** for exploit PoC validation (Shannon-style "No Exploit, No Report")
- [ ] **XBOW benchmark** self-test harness — score MEGATRON against the 104-challenge standard
- [ ] **Multi-agent decomposition** — Scout / Analyzer / Exploiter / Reporter (AutoPentest-AI pattern)
- [ ] **Vulnerability chaining** via knowledge-graph BFS (Web Cache Deception → SSRF → cloud metadata)
- [ ] Prompt improvement so 7B fills the `port` / `service` fields (currently only NVD-injected findings have them)
- [ ] Auto-detect and route by service type: SMB → enum4linux-ng, Windows AD → BloodHound

---

## Attribution

Original CLI + DB schema + PDF exporter by **[Soorya Thejas](https://github.com/sooryathejas)** ([sooryathejas/METATRON](https://github.com/sooryathejas/METATRON)).

Rewrite / rebrand as MEGATRON by **[d3ath69](https://github.com/d3ath69)** — structured output, ground-truth probes, NVD grounding, 2025-2026 tool stack, WAF/OpenAPI/subdomain auto-chains.

---

## License

GPL-3.0 — see [LICENSE](LICENSE).

Upstream [sooryathejas/METATRON](https://github.com/sooryathejas/METATRON) is MIT-licensed; MIT → GPL is a compatible upgrade, so MEGATRON is redistributed under GPL with the original MIT copyright preserved in attribution.

**⚠️ For authorized testing only.** Unauthorized scanning is illegal in most jurisdictions. You are solely responsible for compliance with all applicable laws and terms of service.
