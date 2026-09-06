<div align="center">

# 🤖 MEGATRON

**Autonomous AI penetration testing framework — Ollama-local, structured-output, NVD-grounded.**

*Built for CPTC-style engagements and self-audit of your own infrastructure.*

[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker)](docs/DOCKER.md)
[![Ollama](https://img.shields.io/badge/Ollama-local-white.svg)](https://ollama.com)
[![Latest](https://img.shields.io/github/v/tag/d3ath69/Megatron?label=latest)](https://github.com/d3ath69/Megatron/tags)

</div>

---

## What is MEGATRON?

MEGATRON is a **command-line autonomous pentest agent** that combines a modern 2025-2026 recon-tool stack (20+ specialists) with a **local Ollama LLM** that reads the raw scan output and produces a structured vulnerability report. Every LLM claim is grounded against the NIST NVD API; every service+version tuple it detects triggers a proactive CVE lookup so no known KEV goes unreported.

Unlike hosted alternatives, everything runs on your box — **no cloud API keys, no data leaves your network**, and the whole thing fits inside one `docker compose up`. Designed for CPTC / OSCP-style engagements and pre-competition self-audit.

**Origin:** Started as a rewrite of [sooryathejas/METATRON](https://github.com/sooryathejas/METATRON). Structured-output pipeline, ground-truth probes, NVD grounding, 2025-2026 tool stack, WAF/OpenAPI/subdomain auto-chains, flag-hunt phase, and exploit-execution loop are all d3ath69 work — see [CHANGELOG.md](CHANGELOG.md).

---

## What sets it apart

| Failure mode of most AI pentesters | How MEGATRON handles it |
|---|---|
| LLM invents CVEs → false findings in the report | **NVD verification pass** strips every unverified CVE and downgrades severity |
| LLM is too conservative → misses obvious KEV CVEs (Apache 2.4.49 = CVE-2021-41773) | **Proactive NVD product+version injection** adds grounded CVEs regardless of what the LLM said |
| Regex-parsing free-text LLM output breaks on the first `**bold**` | **Pydantic + Ollama `format=` schema** — zero regex, deterministic JSON |
| Naabu SYN-scan false positives waste minutes of nmap deep-scans | **`_tcp_verify()` two-stage**: raw socket + curl HTTP fallback for docker's dynamic-port range |
| Port 22 open → assumed to be SSH, missed tarpits/honeypots | **`probe_ssh_banner()`** classifier: `REAL_SSH` / `TARPIT_SUSPECT` / `EMPTY_ACCEPT` / `NON_SSH_DATA` |
| No OpenAPI awareness | **Auto-probes 10 conventional paths** → chains `schemathesis` if hit |
| No WAF awareness | **Fingerprints 40 WAF signatures** from response headers (Cloudflare, Akamai, Imperva, F5, Fastly, Vercel, Netlify, Azure Front Door, Alibaba, ByteDance, etc.) |
| Findings without ports/services are noise for report writers | **`_fill_missing_ports()`** cross-references LLM output against scan service-map — guaranteed port/service fill via 60+ product aliases |
| Findings but no proof → useless report | **Exploit-execution loop** invokes matching specialist (sqlmap/dalfox/sstimap/SSRFmap/commix/LFI-probe) and updates findings with `[EXPLOIT-SUCCESS]` proof |
| Passive recon misses obvious leaked flags | **`flag_hunt()` phase** probes 20+ common flag paths + LFI variants, scans all output for `FLAG{...}` markers |

---

## The stack

<div align="center">

| Category | Tools | JSON output |
|---|---|:---:|
| **Ground-truth probes** *(in-house)* | naabu-verify (2-stage TCP+HTTP) · TLS cert grabber (SNI-aware) · SSH banner classifier · WAF fingerprint (40 vendors) · OpenAPI auto-detect · flag-hunt · exploit-execution loop | ✅ |
| **Classic recon** | `nmap` · `whois` · `whatweb` · `curl` · `dig` · `nikto` | mixed |
| **Modern recon (2024-2026)** | `naabu` · `httpx-pd` · `nuclei` (13,619 templates) · `katana` (JS-aware SPA crawler) · `feroxbuster` · `subfinder` (30+ sources) | ✅ |
| **Vulnerability specialists (2025-2026)** | `dalfox` (XSS) · `sqlmap` (SQLi) · `commix` (cmd) · `sstimap` (SSTI) · `SSRFmap` (SSRF) · `crlfuzz` (CRLF) · `schemathesis` (OpenAPI fuzz) · `trufflehog` (secrets) · `semgrep` (SAST) | ✅ |
| **Post-scan** *(optional)* | `gowitness` (screenshots) · `testssl.sh` (deep TLS) · Playwright probe (form/DOM/xhr extraction) · MariaDB persistence · ReportLab PDF/HTML export | mixed |
| **LLM** | Ollama with `qwen2.5:7b-instruct` (35 tok/s, safe default) OR `Qwythos-9B-Claude-Mythos` (114 tok/s, uncensored, recommended for CPTC) | JSON schema-constrained |

</div>

---

## Pipeline flow (the `[p]` menu option)

```
                       naabu -top-ports 1000
                                │
                                ▼
                  filter false positives (TCP handshake)
                                │
                                ▼
        nmap -sV -sC (verified ports)   nmap -sU --top-ports 100
                                │
                                ▼
              openssl s_client → x509  (each TLS-suspect port)
                                │
                                ▼
                      ssh-banner classifier (if port 22)
                                │
                                ▼
                              whois + dig
                                │
                                ▼
                  ── if any web port verified ──
                                │
             ┌──────────────────┼──────────────────┐
             ▼                  ▼                  ▼
        httpx-pd            nuclei-kev         WAF fingerprint
             │                  │                  │
             └──────────────────┼──────────────────┘
                                ▼
                    katana crawl (JS-aware, depth 2)
                                │
                                ▼
                feroxbuster (recursive, SecLists wordlist)
                                │
                                ▼
                dalfox url --format json (XSS on discovered URLs)
                                │
                                ▼
              flag-hunt (20+ common paths + LFI variants)
                                │
                                ▼
                 ── if OpenAPI spec auto-detected ──
                                ▼
                     schemathesis run --checks=all
                                │
                                ▼
                 ── if target is a domain (not IP) ──
                                ▼
                       subfinder -d TARGET -all
                                │
                                ▼
              Ollama structured analysis (Pydantic ScanReport)
                                │
                                ▼
                    POST-VALIDATION (3 passes):
                    1) Verify evidence_lines exist in raw_scan
                    2) NVD-verify every LLM-claimed CVE
                    3) Backfill missing port/service via service-map
                                │
                                ▼
              NVD product+version injection (proactive CVE add)
                                │
                                ▼
              EXPLOIT-EXECUTION LOOP (v0.6.0+):
                    For each Finding with port+service:
                      SQLi   → sqlmap  --batch --dump
                      XSS    → dalfox
                      SSRF   → SSRFmap -m readfiles
                      SSTI   → sstimap
                      CMDi   → commix
                      LFI    → flag-hunt path probes
                    If FLAG{...} captured → severity=critical, confidence=confirmed
                                │
                                ▼
              MariaDB save (5 tables) + optional PDF/HTML export
```

---

## Install

**Fast path — Docker (recommended)**:

```bash
git clone git@github.com:d3ath69/Megatron.git && cd Megatron
docker compose up -d --build
docker compose exec megatron python3 megatron.py
```

First build takes ~10-15 min (downloads all 20+ tools + SecLists 2.5GB). Subsequent builds cached.

**Bare metal — Ubuntu 24.04 / Parrot OS** — full step-by-step in [docs/INSTALL.md](docs/INSTALL.md).

**Prerequisites (host, not in container):**
- Ollama installed with at least one model:
  ```bash
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M   # recommended (114 tok/s, uncensored)
  # or
  ollama pull qwen2.5:7b-instruct   # safer default (35 tok/s)
  ```
- NVIDIA GPU recommended (Ollama uses it on the host, no `nvidia-container-toolkit` needed)
- 8GB+ RAM, 10GB+ disk

---

## Usage

```bash
docker compose exec megatron python3 megatron.py
# or bare metal:
cd ~/Megatron && source venv/bin/activate && python megatron.py
```

Menu → `[1] New Scan` → target → `[p] MEGATRON pipeline (RECOMMENDED)`.

**Individual specialist scans** via single-letter keys:
<div align="center">

| Recon | Specialists | Post-scan |
|:---:|:---:|:---:|
| `[1]` nmap deep | `[x]` dalfox XSS | `[t]` TLS cert |
| `[u]` nmap UDP | `[q]` sqlmap SQLi | `[s]` SSH banner |
| `[7]` naabu | `[c]` commix cmdi | `[w]` WAF detect |
| `[8]` httpx | `[i]` sstimap SSTI | `[F]` flag-hunt |
| `[9]` nuclei-KEV | `[r]` SSRFmap SSRF | `[v]` gowitness |
| `[0]` nuclei full | `[l]` crlfuzz | `[b]` playwright probe |
| `[k]` katana crawl | `[y]` schemathesis | |
| `[f]` feroxbuster | `[h]` trufflehog | |
| `[e]` subfinder | `[g]` semgrep SAST | |

</div>

Chain multiple: `1 8 9 t s` runs nmap + httpx + nuclei-kev + TLS + SSH probe.

---

## Configuration (env vars)

Copy `.env.example` to `.env` and edit. All variables have safe defaults for a fresh install.

| Variable | Default | Effect |
|---|---|---|
| `MODEL_NAME` | Qwythos-9B (Q4_K_M) | Any Ollama-visible tag |
| `MODEL_TEMPERATURE` | `0.5` | `0.1` for qwen2.5, `0.5` for Qwythos |
| `MODEL_THINK` | `false` | `true` only for reasoning models that need it |
| `OLLAMA_HOST` | `host.docker.internal:11434` (Docker) or `localhost:11434` (bare) | Where Ollama runs |
| `OLLAMA_TIMEOUT` | `600` | Bump to `1200` for 27B or slow paths |
| `AUTH_COOKIE` | *(unset)* | e.g. `sessionid=abc; csrftoken=xyz` — threaded through httpx/nuclei/katana/feroxbuster/dalfox/flag-hunt for logged-in scans. v0.8.0 also auto-populated by browser_agent.bootstrap_auth() after a successful login. |
| `AUTH_HEADER` | *(unset)* | e.g. `Authorization: Bearer eyJ...` |
| `PLANNING_MODEL` | *(same as MODEL_NAME)* | v0.8.0: browser-loop planning model. Use a bigger model for better CSS selector picking. |
| `MEGATRON_BROWSER_MAX_ACTIONS` | `15` | v0.8.0: browser exploit-loop action ceiling per finding. |
| `MEGATRON_BOOTSTRAP_USER` / `_PASS` / `_EMAIL` | `megatron_test_user` / `M3g4tr0n!Test123` / `megatron@example.test` | v0.8.0: creds for auto-register+login before exploit loop. |
| `NVD_API_KEY` | *(unset)* | Free at nvd.nist.gov — 5→50 req/30s |
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | `mariadb` / `3306` / `megatron` / `123` / `megatron` | Docker uses compose service names |

---

## XBOW benchmark

MEGATRON includes a harness against the [XBOW Validation Benchmarks](https://github.com/xbow-engineering/validation-benchmarks) — the 104 CTF-style Docker challenges used to score AI pentesters.

```bash
python3 scripts/xbow_bench.py --clone
python3 scripts/xbow_bench.py --run-many XBEN-005-24,XBEN-006-24,XBEN-009-24
python3 scripts/xbow_bench.py --score
```

**Current baseline (v0.6.0, 9 L1+L2 challenges):**
- Findings: 54 across 9 targets, avg 6/challenge
- Flags captured: 0/9 (as predicted — MEGATRON is black-box + no browser exec loop)

**Reference:** [Shannon](https://github.com/KeygraphHQ/shannon) = 96.15% on the full 104 (source-aware + browser-driven exploitation). Closing that gap requires a Playwright agent loop we don't ship yet (foundation is in `run_playwright_probe()`).

The baseline exists to measure trajectory — every future release should re-run the same subset and post the delta.

---

## Roadmap

- [x] Modern 2025-2026 tool stack (v0.4.0)
- [x] Docker one-command install (v0.5.0)
- [x] NVD product+version proactive CVE injection (v0.5.3)
- [x] Auth passthrough for authenticated scans (v0.6.0)
- [x] Flag-hunt phase + exploit-execution loop (v0.6.0)
- [ ] **Multi-agent decomposition** (Scout / Analyzer / Exploiter / Reporter — AutoPentest-AI pattern)
- [ ] **Browser-driven exploit validation** ("No Exploit, No Report" — Shannon-style)
- [ ] **Vulnerability chaining** via knowledge-graph BFS (Web Cache Deception → SSRF → cloud metadata)
- [ ] **Auto-route by service type**: SMB → enum4linux-ng, Windows AD → BloodHound
- [ ] **CI/CD integration**: fail pipeline on `severity >= high` findings

---

## Contributing

Additions welcome — the wrapper pattern in `tools.py` is deliberately simple. To add a new specialist:

1. Wrap the CLI in `tools.py` following the `run_*` pattern (typed args, `subprocess` via `run_tool()`, print announcement)
2. Add to `TOOLS_MENU` with a single-letter menu key
3. Add binary name to `ALLOWED_TOOLS` for LLM `[TOOL:...]` dispatch
4. If it detects a vuln class → add a regex row to `_VULN_SPECIALIST_MAP` in `llm.py` so the exploit-loop can call it
5. Pin its version in the Dockerfile's specialist-tools layer — no `/latest` API calls (GitHub anonymous rate limit is 60/h)

See [docs/INSTALL.md](docs/INSTALL.md) for the full bare-metal install pattern.

---

## Attribution & License

- Original CLI + DB schema + PDF exporter: **[Soorya Thejas](https://github.com/sooryathejas)** ([sooryathejas/METATRON](https://github.com/sooryathejas/METATRON), MIT)
- Structured-output rewrite / MEGATRON rebrand + 2025-2026 stack + XBOW harness + flag-hunt / exploit-execution: **[d3ath69](https://github.com/d3ath69)** (GPL-3.0)

MIT → GPL is a compatible upgrade; the original MIT copyright is preserved in [LICENSE](LICENSE).

**⚠️ For authorized testing only.** Unauthorized scanning is illegal in most jurisdictions. You are solely responsible for compliance with all applicable laws and terms of service.
