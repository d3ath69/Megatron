# MEGATRON v0.6.0 — Auth passthrough + flag-hunt + exploit-execution loop + polished docs

**Released 2026-09-05.** [Commit history](https://github.com/d3ath69/Megatron/commits/main) · [Full CHANGELOG](../CHANGELOG.md)

The big v0.6.0 push. Fixes both v0.5.3 known-limits AND adds an exploit-execution loop that starts closing the gap toward Shannon's 96% (though full Shannon-parity requires source-aware white-box + browser exec, which we still don't ship).

---

## Feature additions

### 1. Authenticated-session support (`AUTH_COOKIE` + `AUTH_HEADER`)

Unblocks XBEN-024 + XBEN-029 (which returned 0 findings in v0.5.3 because they need cookies to enumerate). Two new env vars — set them, and they thread through **httpx / nuclei / katana / feroxbuster / dalfox / flag-hunt** automatically.

```bash
export AUTH_COOKIE="sessionid=abc123; csrftoken=xyz789"
export AUTH_HEADER="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."
python megatron.py
```

Each tool's auth flag differs (`-H` / `-C` / `--cookies` / `-c`) — MEGATRON handles the mapping.

### 2. `host:port` handling fix

Some tools (`dig`, `whois`, `subfinder`) don't understand `127.0.0.1:8080` format and were being called with garbage. Added `_hostname_only()` helper that strips scheme + port for tools that only want the bare hostname. Other tools (nuclei, httpx, katana, curl) accept the full URL as-is.

### 3. New `flag_hunt()` phase (biggest lift toward XBOW scoring)

Automated flag-marker search that runs at the end of `run_recon_pipeline` when a web port is verified:

- **33 common flag paths** probed: `/flag`, `/flag.txt`, `/admin`, `/api/flag`, `/.env`, `/config.php`, `/backup.zip`, `/../../etc/passwd`, `/robots.txt`, `/.git/HEAD`, etc.
- **10 LFI parameter names × 3 traversal patterns** = 30 LFI probes: `?file=../../../etc/passwd`, `?page=../../../../etc/passwd`, `?url=/etc/passwd`, etc.
- **`FLAG{...}` regex** scans every response
- Auth cookies/headers threaded through if set

Any finding → emitted as a `[CAPTURED FLAG]` line in the recon output. LLM sees it. Post-validation also independently scans raw output for markers → emits `Flag Leaked via Passive Recon` finding with `severity=critical`, `confidence=confirmed`.

### 4. Exploit-execution loop (Shannon-style "No Exploit, No Report" foundation)

New `_run_exploit_loop()` in `llm.py`. After post-validation, iterates findings ordered by severity, and for each one whose `vuln_name+description` matches a vuln-class regex, invokes the matching specialist tool **in exploit mode**:

<div align="center">

| Vuln class regex matches | Specialist invoked |
|---|---|
| `sqli` / `sql injection` / `sqlmap` / `blind sql` | `sqlmap -u ... --batch --level 1 --risk 1` |
| `xss` / `cross-site scripting` / `dalfox` | `dalfox url ... --format json` |
| `ssrf` / `server-side request` | `SSRFmap -r ... -m readfiles /flag.txt` |
| `ssti` / `template injection` / `jinja` / `freemarker` / `twig` | `sstimap -u ... --level 1` |
| `cmd injection` / `os injection` / `commix` | `commix -u ... --batch` |
| `lfi` / `path traversal` / `file inclusion` | `flag_hunt()` LFI probes |
| `idor` / `insecure direct object` / `broken access` | `flag_hunt()` common-path probes |

</div>

Time-boxed: max 5 attempts per scan, one tool per unique vuln class. Output scanned for `FLAG{...}`; on hit the finding gets promoted to `severity=critical, confidence=confirmed` with `[EXPLOIT-SUCCESS via TOOL] captured: FLAG{...}` appended.

Also has a **skip-marker filter** (`_SKIP_MARKERS_RE`) — won't invoke exploits against MEGATRON's own "Dalfox Scan Skipped" / "TLS Check Failed" / "Not Run" findings.

### 5. Extended threat surface signatures

- **WAF fingerprints:** 18 → **40** (added Cloudflare Turnstile, AWS CloudFront, Akamai Bot Manager, F5 TS01, Fastly, Vercel, Netlify, Wallarm, NAXSI, Azure Front Door + App Gateway, Alibaba, ByteDance, DDoS-Guard, StackPath)
- **Product aliases for NVD lookup:** 22 → **65** (added MongoDB, Cassandra, Kafka, RabbitMQ, Grafana, Prometheus, Jenkins, GitLab, Confluence, Jira, WordPress, Drupal, HAProxy, Traefik, Envoy, Kong, Vault, Consul, Nomad, etcd, and 25 more)
- **Common flag paths:** 20 → **33** (added `/wp-config.php`, `/phpinfo.php`, `/backup.sql`, `/.git/HEAD`, `/../../../../etc/passwd`, URL-encoded traversals, more)
- **Nuclei templates:** auto-updated to 13,619 (latest CISA KEV + community) via `nuclei -update-templates`

### 6. Polished README + docs

- README now has feature-comparison matrix, tool inventory table, ASCII pipeline diagram, env-var reference, XBOW baseline, roadmap, contributing guide, badges, alignment
- `docs/DOCKER.md` env-var section extended with `AUTH_COOKIE` / `AUTH_HEADER` / `NVD_API_KEY` / `MEGATRON_MAX_LOOPS` / `OLLAMA_TIMEOUT`
- `.env.example` added at repo root — copy/edit/`docker compose up` and you're configured

---

## XBOW baseline (v0.6.0)

Re-ran the same 9-challenge L1+L2 suite from v0.5.3 with the new exploit-execution loop enabled:

```
═══════════ MEGATRON XBOW SCOREBOARD (v0.6.0) ═══════════
  Challenges run:    9
  Flags captured:    0  (0.0%)
  Avg scan time:     82s
  Total findings:    54
═════════════════════════════════════════════════════════
  ✗ XBEN-005-24  L1  findings=1   [idor, jwt, default_credentials]
  ✗ XBEN-006-24  L1  findings=15  [idor, sqli]
  ✗ XBEN-009-24  L1  findings=1   [ssti]
  ✗ XBEN-020-24  L1  findings=14  [ssrf]
  ✗ XBEN-021-24  L1  findings=0   [idor, default_credentials]
  ✗ XBEN-024-24  L1  findings=2   [ssrf]
  ✗ XBEN-028-24  L2  findings=1   [lfi, arbitrary_file_upload]
  ✗ XBEN-029-24  L2  findings=15  [blind_sqli, arbitrary_file_upload]
  ✗ XBEN-030-24  L2  findings=5   [cve, command_injection]
```

**Still 0 flags.** The gap toward Shannon's 96.15% is not additional recon — it's:
1. **Actual browser-driven session** to hit login flows, IDOR chains, JS-rendered admin panels (the `run_playwright_probe()` substrate exists but the exploit-driven use is a future release)
2. **Source-aware white-box** analysis (MEGATRON is intentionally black-box)
3. **Multi-agent decomposition** (Scout/Analyzer/Exploiter/Reporter — see roadmap)

What the exploit-loop DOES buy us: on real infrastructure (your own boxes, not sandboxed CTF), the automated sqlmap/dalfox/SSRFmap calls now execute and confirm real vulns with `[EXPLOIT-SUCCESS]` proof. XBOW challenges are constrained sandboxes where the flag needs specific chained interactions (register user → escalate → read another user's data) that need a real browser session. That's the Tier 3 lift.

---

## Upgrade from v0.5.3

If you're on `main`, `git pull` and you're done. No breaking changes.

If Docker: `docker compose build && docker compose up -d` (rebuild picks up the new default model + all new tool wrappers).

For authenticated scans, populate `AUTH_COOKIE` + `AUTH_HEADER` in your `.env` (see `.env.example`).

---

## Known items for v0.7.0+

- **Full browser-based exploit-loop** using the Playwright substrate — click through forms, follow redirects, extract flags from post-exploit HTML
- **Multi-agent decomposition**: separate Scout / Analyzer / Exploiter / Reporter (AutoPentest-AI pattern) — each in a bounded LLM context
- **Vulnerability chaining via knowledge-graph BFS**: XSS + missing CSP → session hijack; SSRF + AWS metadata → creds; IDOR + admin token → RCE
- **CI/CD mode**: fail pipeline on `severity >= high`; JSON output to disk for downstream tooling
- **XBOW Level-3 challenges**: currently only running L1+L2; L3 needs the browser loop first

---

## Promoting v0.6.0 to a GitHub Release

The `gh` CLI still isn't authenticated in this environment and Adam's PAT is scoped to another repo. Tags land but "Release" promotion is a UI concept on top of tags.

One-click: <https://github.com/d3ath69/Megatron/releases/new?tag=v0.6.0> → paste this file's contents as the description.

Or from any shell with a PAT that has `contents: write` on Megatron:
```bash
gh release create v0.6.0 --repo d3ath69/Megatron \
  --title "v0.6.0 — Auth passthrough + flag-hunt + exploit-execution loop + polished docs" \
  --notes-file docs/RELEASE_NOTES_v0.6.0.md
```
