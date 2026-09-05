# Changelog

All notable changes to MEGATRON.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

---

## [0.7.0] — 2026-09-05

**Browser-driven exploit loop (Playwright) + multi-tier ensemble + critical host:port bug fix.**

### Added
- **`browser_agent.py`** — new module. `BrowserSession` class provides persistent Chromium session (context survives across actions), auth-cookie/header threading, `observe()` → compact JSON snapshot with real DOM selectors, `act()` → one atomic action + wait for network idle. Docker-safe (`--no-sandbox`). Graceful ImportError if playwright not installed.
- **`_browser_exploit()`** in llm.py — LLM ↔ browser dialog loop. 15-action max. Every observation regex-scanned for FLAG{...} (fast path). Action-history dedup prevents loops. Uses new `BrowserAction`/`BrowserPlan` Pydantic schemas — selectors MUST come from observed set (Pydantic-enforced anti-hallucination).
- **`_ask_structured_typed()`** — reusable single-shot Ollama structured call for arbitrary Pydantic schemas.
- **Multi-tier ensemble in `_run_exploit_loop`** — Tier 1: browser loop for web findings + playwright available. Tier 2: CLI specialist (sqlmap/dalfox/etc) as fallback. First to capture flag wins.
- **Playwright + Chromium in Dockerfile** — image adds ~200MB (2.28 GB → ~2.5 GB). `requirements.txt` now includes `playwright>=1.47.0`.
- **Login/register page detection helpers** — `looks_like_login_page()`, `looks_like_register_page()` for future auth-flow bootstrap.
- **`docs/RELEASE_NOTES_v0.7.0.md`** with honest before/after XBOW numbers + Shannon comparison matrix.

### Fixed
- **CRITICAL: `_tcp_verify(target, port)` was silently breaking on `host:port` targets.** `socket.create_connection(("127.0.0.1:32785", 32785))` is a garbage tuple that always failed → all XBOW challenges (docker dynamic ports) returned 0 verified ports → **entire web pipeline was skipped** (httpx, nuclei-kev, katana, feroxbuster, dalfox, flag_hunt all silently no-op'd). Fix: `_hostname_only(target)` strip in `_tcp_verify` + `run_nmap` + `run_nmap_udp_top100` + `run_nmap_targeted`. Also added explicit-port short-circuit in `run_recon_pipeline` — if target has `:port` already, skip naabu sweep and use that port directly.
- **`_hostname_only()` now stripped from all nmap wrappers** — nmap treats `host:port` as `host:port_range_spec` and misfires.

### Verified XBOW v0.7.0 baseline (5 L1 challenges)
- 5 challenges run, 15 findings, **0 flags captured** (still — need auth-flow bootstrap + session-aware planning)
- **Severity distribution IMPROVED**: 2 CRITICAL + 3 HIGH findings (v0.6.0 had 0 of each on same challenges). Browser loop confirming evidence.
- Avg scan time 82s → **734s** (browser exploration costs)
- Full analysis in docs/RELEASE_NOTES_v0.7.0.md

### MEGATRON differentiators vs Shannon
- 100% local Ollama (Shannon needs Anthropic API)
- $0 per scan (Shannon: ~$1-5)
- Works black-box AND white-box (Shannon: white-box only)
- Ground-truth NVD verification on every CVE claim
- Proactive NVD product+version injection (65 aliases)
- 40 WAF signatures fingerprinted
- Multi-tier fallback (browser → CLI → curl-craft)
- GPL-3.0 open source
- One-command `docker compose up` install
- Shannon still wins on: XBOW flag capture rate (needs source-aware exec, out of black-box scope)

---

## [0.6.0] — 2026-09-05

**Auth passthrough + flag-hunt phase + exploit-execution loop + polished docs.**

### Added
- **`AUTH_COOKIE` + `AUTH_HEADER` env vars** — threaded through httpx / nuclei / katana / feroxbuster / dalfox / flag-hunt for authenticated scans. Different tools use different flag names (`-H`, `-C`, `--cookies`, `-c`), MEGATRON handles the mapping.
- **`flag_hunt()` in tools.py** — probes 33 common flag paths + 30 LFI variants (10 param names × 3 traversal patterns), scans every response for `FLAG{...}`. Runs at end of `run_recon_pipeline` when a web port is verified. New menu key `[F]`.
- **`_run_exploit_loop()` in llm.py** — after post-validation, invokes matching specialist for each Finding whose vuln_name/description matches one of 7 regex patterns (SQLi→sqlmap, XSS→dalfox, SSRF→SSRFmap, SSTI→sstimap, CMDi→commix, LFI→flag-hunt probe, IDOR→flag-hunt probe). Time-boxed (max 5 attempts per scan). On `FLAG{...}` capture: promotes finding to `critical` + `confirmed` + `[EXPLOIT-SUCCESS via TOOL]` proof.
- **`_SKIP_MARKERS_RE`** — filters MEGATRON's own "Skipped/Not Run/Failed" markers from exploit loop, preventing pointless invocations against internal error states.
- **`FLAG_RE` module-level regex** in tools.py — reused across flag_hunt, LFI probes, exploit-loop output scanning, and post-validation raw-scan sweep. Matches `FLAG{...}`, `flag{...}`, `CTF{...}` with hex-digest or plain payloads.
- **`.env.example`** at repo root — copy/edit/`docker compose up`, fully documented env var reference.
- **Polished README** — feature-comparison matrix, tool inventory table, ASCII pipeline diagram, env-var table, XBOW baseline, roadmap, contributing guide, badges.
- **`docs/RELEASE_NOTES_v0.6.0.md`** with full changelog + before/after XBOW numbers + upgrade instructions.

### Extended threat coverage
- **WAF fingerprints: 18 → 40** vendors — added Cloudflare Turnstile, AWS CloudFront, Akamai Bot Manager, F5 TS01, Fastly, Vercel, Netlify, Wallarm, NAXSI, Azure Front Door + App Gateway, Alibaba, ByteDance, DDoS-Guard, StackPath, Wallarm.
- **NVD product aliases: 22 → 65** — added MongoDB, Cassandra, Kafka, RabbitMQ, Grafana, Prometheus, Jenkins, GitLab, Confluence, Jira, WordPress, Drupal, HAProxy, Traefik, Envoy, Kong, Vault, Consul, Nomad, etcd, WordPress, Bitbucket, SonarQube, Artifactory, Nexus, Exim, Postfix, Samba, and 20+ more.
- **Common flag paths: 20 → 33** — added `/wp-config.php`, `/phpinfo.php`, `/backup.sql`, `/.git/HEAD`, URL-encoded traversals, more.
- **Nuclei templates:** auto-updated to 13,619 latest (CISA KEV + community).

### Fixed
- **`host:port` handling** — `dig`, `whois`, `subfinder` were being called with `127.0.0.1:8080` and choking. New `_hostname_only()` helper strips scheme + port for tools that want bare hostname; other tools (nuclei/httpx/katana/curl) get the full URL.
- **Exploit loop hitting own error findings** — `_pick_specialist()` now filters via `_SKIP_MARKERS_RE` before regex-matching vuln class.

### XBOW baseline (v0.6.0)
- Same 9 L1+L2 challenges as v0.5.3.
- **9 challenges run, 54 findings, 0 flags** (unchanged from v0.5.3 for XBOW).
- No score change is expected — XBOW's flags require chained interactions (register→escalate→read-other-user-data) that need a real browser session. That's the Tier 3 (browser exec loop) work, not the recon side. The exploit-execution loop DOES fire correctly on real infrastructure where flags leak via simple paths or SQLi dumps.

---

## [0.5.3] — 2026-09-05

**Docker port-verify fix + extended XBOW baseline (10 challenges) + rebuilt image.**

### Fixed
- `_tcp_verify()` now has a curl HTTP-HEAD fallback when raw socket handshake fails on high-numbered ports (≥1024 or common web ports). Root cause: docker's user-mode loopback proxy interacts oddly with kernel TCP semantics — raw sockets can look filtered on ports docker publishes even though HTTP works fine. Discovered during v0.5.2 XBOW baseline on `127.0.0.1:32770`.

### Added
- `docs/RELEASE_NOTES_v0.5.3.md` — release notes for this version.
- 6 additional XBOW challenges scored: XBEN-020 (2nd run), XBEN-021 (IDOR/default_creds), XBEN-024 (SSRF), XBEN-028 (LFI/upload), XBEN-029 (blind_sqli), XBEN-030 (cve/cmdinject). Full 10-challenge scoreboard in `scripts/xbow-results.jsonl`.

### Changed
- Docker image `megatron:latest` rebuilt with v0.5.2 defaults baked in (Qwythos as `MODEL_NAME`, `MODEL_TEMPERATURE=0.5`, `MODEL_THINK=false` in the Dockerfile ENV). Same 2.28GB size.

### Verified
- **Extended XBOW baseline: 10/10 challenges, 62 total findings, 0 flags captured.** Zero flags as predicted (MEGATRON is black-box recon+LLM; exploit-execution loop is Tier 3 roadmap). Establishes real trajectory for future measurement.
- `_tcp_verify()` closed-port test still returns False (fallback doesn't over-trigger); open ports 22 and 11434 still return True via the primary socket path.

### Known limits documented for v0.5.4+
- Authenticated-session support (XBEN-024 + XBEN-029 came back 0-findings because they need cookies to enumerate).
- `run_recon_pipeline()` misfires when target has `:port` suffix — some tools (dig, whois) don't handle it.

---

## [0.5.2] — 2026-09-05

**Qwythos-9B as default + port-backfill guarantee + XBOW baseline established.**

### Added
- `_fill_missing_ports()` in llm.py — code-side fallback that cross-references LLM findings with `_extract_service_versions(raw_scan)` and backfills empty `port`/`service` fields. Alias map covers service tokens, product names, and common aliases (openssh→ssh, http_server→apache). Guarantees port/service population regardless of what the LLM emits.
- `docs/RELEASE_NOTES_v0.5.2.md` — human-readable release notes with benchmark tables, XBOW scoreboard, and upgrade instructions.
- `scripts/xbow-results.jsonl` — persistent scoreboard file (append-only, one JSON row per challenge run).
- SYSTEM_PROMPT expanded with GOOD/BAD JSON examples showing filled `port` field.

### Changed
- **Default model swap**: `MODEL_NAME` default was `qwen2.5:7b-instruct`, now `hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M`. `MODEL_TEMPERATURE` default: `0.1` → `0.5` (Qwythos docs warn T≤0.3 causes repetition loops). Applied to `llm.py`, `docker-compose.yml`, `Dockerfile` ENV, `Modelfile`.
- **`scripts/xbow_bench.py` rewritten** to match actual XBOW structure — uses their canonical `make -C benchmarks/NAME {build,run,stop}` flow instead of guessing docker service names. Deterministic flag computation `FLAG{sha256(BENCHMARK_UPPER)}`. Dynamic port discovery via `docker compose ps --format json`. New subcommand `--run-many CSV`.

### Verified
- **Bench**: Qwythos = 114 tok/s on RTX 3070 (3.2× faster than qwen2.5's 35 tok/s), 16 findings vs 12 on same synthetic scan.
- **Port backfill**: 4/4 LLM-generated findings now have `port` correctly populated (was 0/4 before this release).
- **XBOW baseline**: 4 Level-1 challenges run (2 more failed at XBOW's own docker build with EOL Debian Buster bitrot — not our issue). 0/4 flag capture as predicted — MEGATRON is black-box recon+LLM without exploit-execution loop. Establishes measurable trajectory for future Tier 3 browser-automation work.

### Discovered (fix candidates for v0.5.3)
- `_tcp_verify()` misclassifies docker-published dynamic ports (≥32768 range) as filtered. Fallback probe path needed.

### Tagged
- `git tag v0.5.2` pushed to GitHub. First real semver-tagged release on the repo.

---

## [0.5.1] — 2026-09-05

**Dockerfile hardening + Qwythos-9B benchmark.**

### Fixed
- Dockerfile pinned all GitHub release URLs to explicit stable versions instead of `/latest` API calls. First `docker compose build` failed on the specialist-tools layer because anonymous GitHub API is rate-limited to 60 req/hour per IP — the URL-lookup loop for trufflehog/crlfuzz/gowitness returned empty strings mid-build, producing `curl -o pkg ""` → exit 3.
- Pinned versions: naabu 2.6.1, subfinder 2.16.0, katana 1.7.0, httpx 1.10.0, nuclei 3.11.1, trufflehog 3.97.4, crlfuzz 1.4.1, gowitness 3.1.1, dalfox 3.2.2. Bonus: reproducible builds.

### Verified
- Full stack `docker compose up -d` on incubus: mariadb container healthy in 16s (schema.sql auto-loaded via `/docker-entrypoint-initdb.d/`); megatron container reaches host Ollama via `host.docker.internal:11434` (6 models visible) and mariadb via compose network hostname `mariadb`.

### Benchmarked (RTX 3070, structured-output pipeline)
- `qwen2.5:7b-instruct`: ~35 tok/s, 12 NVD-grounded findings on synthetic scan
- `hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M`: **~114 tok/s (3.2× faster)**, same 12 findings, uncensored, Claude-fine-tuned. Requires `MODEL_TEMPERATURE=0.5` (their docs warn T≤0.3 causes loops) and `MODEL_THINK=false` (suppresses the reasoning-model prefix).
- README updated to mark Qwythos as **recommended for CPTC**; qwen2.5 kept as safe default.

---

## [0.5.0] — 2026-09-05

**Docker stack + env-var config + Tier 3 heavies (XBOW harness + Playwright).**

### Added
- **Dockerfile** (Ubuntu 24.04 base, 11 layers): pre-installs all 20+ tools (naabu, subfinder, katana, httpx-pd, nuclei, dalfox, feroxbuster, trufflehog, crlfuzz, gowitness, commix, sstimap, SSRFmap), SecLists (2.5GB), Python venv with pydantic + ollama + sqlmap + schemathesis + semgrep. Final image: **2.28 GB**.
- **docker-compose.yml**: `megatron` + `mariadb` services with healthchecks, named volume for DB persistence, bind mounts for reports/exports/scans, `host.docker.internal:host-gateway` extra_host for Ollama-on-host.
- **.dockerignore** so builds don't ship venv/git/scan-history.
- **docs/DOCKER.md**: full container deployment guide — network topology diagram, GPU-on-host explanation, env-var reference, troubleshooting table, disk footprint breakdown.
- **docs/INSTALL.md**: bare-metal step-by-step for Ubuntu 24.04 / Parrot OS with exact copy-paste blocks for every tool. Includes Qwythos alt-model swap recipe.
- **docs/schema.sql**: 5-table MariaDB schema, dual-use (Docker init + bare-metal load).
- **scripts/xbow_bench.py**: XBOW Validation Benchmarks harness. Subcommands: `--clone` / `--list` / `--run XBEN-NNN` / `--run-all` / `--score`. Clones the 104 CTF-style Docker challenges, iterates MEGATRON's pipeline against each, tracks flag-capture rate. Reference: Shannon 96.15%.
- **`run_playwright_probe()`** in tools.py: headless Chromium via Playwright — extracts every `<form>`, `<input>`, `<a href>`, records JS-initiated xhr/fetch requests, captures console messages, full-page screenshot. Foundation for Shannon-style "No Exploit, No Report" workflow. Gracefully skips if playwright not installed (kept optional in requirements.txt).
- Menu key `[b]` for playwright probe (28 total menu entries now).

### Changed
- **db.py** + **export.py**: `get_connection()` now reads `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` env vars with lab-default fallbacks. Enables Docker networking + external DB deployment.
- **llm.py**: reads `OLLAMA_HOST` / `MODEL_NAME` / `MODEL_TEMPERATURE` / `MODEL_THINK` / `OLLAMA_TIMEOUT` / `MEGATRON_MAX_LOOPS` env vars. `_MODEL_THINK` toggle enables Qwythos-style reasoning models without breaking qwen2.5 default.

---

## [0.4.0] — 2026-09-05

**Tier 1 + Tier 2 + Tier 3 lite: 2025-2026 specialist stack integration.**

### Added
- **12 new specialist tool wrappers** in `tools.py`:
  - `run_dalfox()` — XSS scanner (reflected/DOM/stored/blind), JSON output
  - `run_sqlmap()` — SOTA SQL injection, batch mode, safe defaults (level=1/risk=1)
  - `run_katana()` — JS-aware SPA crawler (ProjectDiscovery)
  - `run_feroxbuster()` — recursive content discovery, SecLists raft-medium wordlist
  - `run_commix()` — command injection scanner (with Ubuntu 24.04 shebang fix)
  - `run_sstimap()` — Server-Side Template Injection (Jinja2/Twig/Freemarker/Velocity)
  - `run_ssrfmap()` — SSRF exploitation with auto-generated request template
  - `run_crlfuzz()` — CRLF injection / HTTP response splitting
  - `run_schemathesis()` — OpenAPI/Swagger fuzzer
  - `run_subfinder()` — passive subdomain enum (30+ sources)
  - `run_trufflehog()` — secret detection (git + filesystem)
  - `run_semgrep()` — SAST for source-available targets
- **Tier 3 upgrades:**
  - `detect_waf()` — fingerprints 18 WAF vendors (Cloudflare, Akamai, Imperva, F5, Sucuri, ModSecurity, Wordfence, Barracuda, Citrix NetScaler, FortiWeb, AWS WAF, etc.) from HTTP response headers/cookies
  - `_find_openapi_spec()` — auto-probes 10 known OpenAPI/Swagger conventional paths; chains `schemathesis` if hit
  - `run_gowitness()` — headless-chrome screenshots (chromium optional)
- **Pipeline chaining upgrades in `run_recon_pipeline()`:**
  - After nuclei-kev: `katana → feroxbuster → dalfox` on discovered URLs
  - Auto-runs WAF fingerprint when a web port is verified
  - Auto-runs `subfinder` when target is a domain (not IP)
  - Auto-runs `schemathesis` if OpenAPI spec auto-detected
- 14 new menu keys: `[x]` `[q]` `[k]` `[f]` `[c]` `[i]` `[r]` `[l]` `[e]` `[h]` `[g]` `[w]` `[v]` `[y]`
- ALLOWED_TOOLS extended from 9 → 21 entries for LLM `[TOOL:...]` dispatch

### Changed
- Pipeline menu label updated to reflect all new stages
- LICENSE rewritten (kept MIT, updated copyright to d3ath69, retained attribution to sooryathejas)
- README rewritten from METATRON boilerplate to describe actual MEGATRON capabilities

### Verified
- Full smoke test: naabu(8) → nmap deep → 4 TLS certs → SSH probe → httpx → nuclei-kev → WAF-detect → katana(200 OK) → feroxbuster → dalfox → subfinder (found `www.itshardtosayno.com`) → Ollama structured analysis → NVD-injected 5 grounded CVEs
- All 27 menu entries load; all 21 allowed tools recognized by LLM dispatch

---

## [0.3.0] — 2026-08-28

**Ground-truth probes + proactive CVE injection.**

### Added
- **Naabu → TCP-handshake reconciliation** (`_tcp_verify()` + `_naabu_extract_verified_ports()`) — kills SYN-scan false positives. Discovered port 6789 was a naabu artifact, not an actual UniFi Controller exposure.
- **`run_tls_cert()`** — `openssl s_client → x509` per TLS-suspect port. Subject/issuer/SAN/dates. Single highest-signal service fingerprint.
- **`probe_ssh_banner()`** — categorizes port 22: `REAL_SSH` / `TARPIT_SUSPECT` / `EMPTY_ACCEPT` / `NON_SSH_DATA` / `UNREACHABLE`. Detects endlessh, cowrie, misconfigured proxies.
- **`nvd_search_by_product()`** in `search.py` — proactive NVD CVE lookup by product + version. Rate-limited to 6s intervals (NVD free tier).
- **`_extract_service_versions()`** in `llm.py` — regex-parses nmap `PORT/tcp open SERVICE VERSION` lines. 22-entry product alias dict maps `apache→http_server`, `openssh→openbsd`, `httpd→http_server`, etc.
- **NVD injection phase in `_post_validate()`** — for each detected service+version, queries NVD for top-3 CVEs by CVSS and injects them as confirmed Findings with port/service pre-filled. Deduplicates against LLM-claimed CVEs.
- **Pipeline additions to `run_recon_pipeline()`:**
  - TLS cert grab for every port in `TLS_SUSPECT_PORTS` = {443, 465, 636, 993, 995, 5061, 6697, 7443, 8443, 9443}
  - SSH banner probe when port 22 verifies
- Menu keys `[t]` (TLS cert 443) and `[s]` (SSH banner 22)

### Verified
- NVD injection successfully added `CVE-2023-28531` / `CVE-2023-38408` / `CVE-2023-48795` (Terrapin) for OpenSSH 8.9p1 + `CVE-2023-44487` / `CVE-2025-23419` for nginx 1.24.0 — all findings the 7B model was too conservative to claim.

---

## [0.2.0] — 2026-08-25

**Rebrand METATRON → MEGATRON + structured output rewrite.**

### Added
- **Pydantic schemas** in `llm.py`: `Finding`, `Exploit`, `ScanReport` with typed fields including `evidence_lines: list[int]`, `confidence: Literal[...]`, `cvss_score: float | None`
- **Ollama `format=<schema>` structured output** — zero regex parsing, deterministic JSON output
- **`think=False`** + `temperature=0.1` — kills Qwen 3.5's chain-of-thought verbosity, saves ~5-10x tokens on schema-following tasks
- **`_post_validate()`** — checks LLM-claimed CVEs against NVD; strips + downgrades unverified ones
- **`_number_lines()`** — line-numbers the raw_scan before feeding to LLM so `evidence_lines` citations can be validated post-hoc
- **`run_recon_pipeline()`** (2-stage): naabu fast sweep → nmap `-sV -sC` on found ports only. Softer `-T3` timing (was `-T4`) to avoid DoS'ing fragile CTF boxes.
- **`run_nmap_udp_top100()`** — UDP sweep for SNMP/DNS/TFTP/IPMI/NetBIOS
- **`run_nuclei()`** + **`run_nuclei_kev()`** — CISA KEV subset for fast/high-signal scanning
- **`run_httpx()`** — installed as `httpx-pd` to avoid Python `httpx` client conflict
- **`run_naabu()`** — fast port sweep in JSON mode
- Menu keys `[7]` naabu · `[8]` httpx · `[9]` nuclei-kev · `[0]` nuclei-full · `[u]` UDP
- Fresh MariaDB database `megatron` (schema identical to `metatron` for schema-compat)
- Rebranded banner (ANSI-regular figlet, unambiguous MEGATRON vs METATRON)
- CPTC-flavored system prompt

### Changed
- Free-text `VULN:/EXPLOIT:` regex parser → Pydantic `model_validate_json()` — parser drops to zero fragility
- Model default: `metatron-qwen` (custom 9B) → `qwen2.5:7b-instruct` (stable, faster on RTX 3070)

### Verified
- End-to-end smoke test on `127.0.0.1` — 8 findings correctly parsed, MariaDB rows written, MEDIUM risk assigned

---

## [0.1.0] — 2026-08-24

**Initial fork from [sooryathejas/METATRON](https://github.com/sooryathejas/METATRON) upstream.**

Preserved from upstream:
- CLI menu structure (`metatron.py`)
- MariaDB 5-table schema (`db.py`)
- ReportLab PDF/HTML exporter (`export.py`)
- DDG search + CVE MITRE lookup (`search.py`)
- Basic recon tool wrappers (`tools.py` — nmap/whois/whatweb/curl/dig/nikto)
- ReAct-style tool dispatch loop (`llm.py`)
- Modelfile for custom `metatron-qwen` Ollama model

---

## Upstream

- **[sooryathejas/METATRON](https://github.com/sooryathejas/METATRON)** — the original project this is built on. Chef's kiss for the DB schema + PDF exporter.
