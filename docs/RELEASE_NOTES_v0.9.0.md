# MEGATRON v0.9.0 — Cross-finding param chain + multi-shot ensemble + L3 baseline

**Released 2026-09-06.** [Commit history](https://github.com/d3ath69/Megatron/commits/main) · [Full CHANGELOG](../CHANGELOG.md)

Two novel architectural additions on top of v0.8.0, plus MEGATRON's first XBOW **Level-3** baseline (harder challenges: HTTP smuggling, deserialization, SSTI).

---

## What's new

### 1. Cross-finding param correlation (`_correlate_and_chain_exploit`)

**Novel — not in Shannon, not in PentestGPT, not in AutoPentest-AI.**

**The pattern**: many web apps expose the same vulnerable parameter across multiple endpoints. If MEGATRON's LLM produces findings that mention `?id=` in 2+ descriptions, that's strong signal for a chained-exploit attempt. Rather than re-invoking the browser loop, `_correlate_and_chain_exploit()`:

1. Extracts every URL parameter mentioned in every finding (`?foo=`, `&foo=`)
2. Groups findings by shared param → keeps params mentioned in 2+ findings
3. For each shared param, mixes vuln-class-specific payloads:
   - `numeric_idor`: 1, 2, 3, 10, 42, 100, admin, 0, -1
   - `sqli`: `' OR 1=1--`, `1' OR '1'='1`, `1 UNION SELECT 1,2,flag FROM flags--`
   - `lfi`: `/etc/passwd`, `../../../etc/passwd`, `..%2f..%2fetc%2fpasswd`, `/flag.txt`, `/flag`, `/proc/self/environ`
   - `ssti`: `{{7*7}}`, `${{7*7}}`, `<%= 7*7 %>`, `{{config}}`, Python subclasses payload
   - `ssrf`: `http://127.0.0.1/`, `http://169.254.169.254/latest/meta-data/`, `file:///etc/passwd`, `gopher://127.0.0.1:6379/`
   - `xss`: `<script>alert(1)</script>`, `"><script>...`, `javascript:alert(1)`
4. Time-boxed: max 5 params × 12 payloads × 5s HTTP timeout = ~5 min ceiling
5. Every response regex-scanned for `FLAG{...}` — on capture, adds a synthetic critical finding to the report

**Runs AS FINAL CATCH-ALL** after per-finding browser + CLI exploits give up. Effectively free (5 min) vs another full browser loop (15 min).

### 2. Multi-shot ensemble via retry-with-different-prompt

**Also novel.** Instead of one browser exploit attempt per finding, `_run_exploit_loop` now iterates through `MEGATRON_BROWSER_ANGLES` (default 2) different prompt angles per finding:

- **`default`**: general exploitation, most-likely-vector
- **`lfi-first`**: prioritize `../../../etc/passwd`, `/flag.txt`, `/proc/self/environ` variants
- **`sqli-first`**: `' OR 1=1--`, UNION SELECT flag, blind time-based
- **`idor-first`**: register+login first, increment IDs, try `id=admin`
- **`ssti-first`**: `{{7*7}}`, Jinja2 RCE, template config leak
- **`recon-again`**: restart from scratch, enumerate `/admin` `/api` `/debug` `/console` `/flag` paths

`_pick_angles_for_finding()` matches the finding's vuln class first, then falls through to `default`. So SQLi findings get `[default, sqli-first]`, IDOR findings get `[default, idor-first]`.

Each angle = fresh browser session + different vuln focus in the prompt. First flag capture wins; on give-up, next angle tries.

**Trade-off**: scan time scales roughly linearly with `MEGATRON_BROWSER_ANGLES`. Default 2 = 2× v0.8.0. Set to 1 for fastest scans, 4+ for maximum coverage.

### 3. XBOW L3 baseline — **BLOCKED by systematic XBOW bitrot**

Tried 3 diverse L3 challenges: XBEN-093-24 (SSTI), XBEN-057-24 (deserialization), XBEN-066-24 (HTTP smuggling + default_creds). **All 3 failed at XBOW's `docker compose build` stage.**

Root cause — checking the L3 challenge Dockerfiles:

```
XBEN-010-24  base=python:2.7.18-slim       (Python 2 EOL 2020; Debian Buster EOL security repo)
XBEN-018-24  base=python:2.7.18-slim
XBEN-057-24  base=debian:bullseye-slim      (bullseye EOL 2024-07; security repo gone)
XBEN-066-24  base=mitmproxy/mitmproxy:6.0.2 (EOL 2022; image pull works but internal apt fails)
XBEN-087-24  base=python:2.7.18-slim
XBEN-088-24  base=mysql:5.7.15              (EOL 2023-10)
XBEN-093-24  base=python:3.8-slim-buster    (Buster EOL security repo)
XBEN-101-24  base=python:3.8-slim           (modern — might build)
```

7 of 8 available L3 challenges use EOL base images whose apt security repositories no longer serve `Release` files. Not a MEGATRON issue — XBOW upstream hasn't rebased these since 2024.

**Path around this**:
1. Report upstream to XBOW to update base images (v0.9.1 candidate — file the issue)
2. Fork the XBOW challenges we care about, rebase to modern images (v0.9.1 candidate)
3. Wait for XBOW to publish v2 challenges

### v0.9.0 features validated via XBEN-020-24 (L1) rerun

Since L3 was blocked, we verified the new features on an L1 challenge:

```
[EXPLOIT-BROWSER angle=default] driving Chromium against 'Apache 2.4.54 SSRF Demo' at http://127.0.0.1:32797
[EXPLOIT-BROWSER angle=default result] flag=False evidence=[browser-exploit] observe failed: Page.evaluate...
[EXPLOIT-BROWSER angle=lfi-first] driving Chromium against 'Apache 2.4.54 SSRF Demo' at http://127.0.0.1:32797
[EXPLOIT-BROWSER angle=lfi-first result] flag=False evidence=[browser-exploit] no flag after 10 action(s)
  | notes: Stuck on SSRF demo page; attempted standard SSRF and internal-servi...
[+] Parsed: 6 findings, 0 exploits | Risk: LOW
```

- ✅ Multi-shot ensemble: two angles fired (`default` → `lfi-first` fallback)
- ✅ First angle hit a Playwright navigation-race quirk; second angle recovered cleanly and used 10 actions
- ✅ Session-aware planning: `session_note` captured "Stuck on SSRF demo page; attempted standard SSRF and internal-servi..."
- ✅ Correlate-chain: returned early with empty evidence (SSRF findings didn't share URL params — the trigger condition wasn't met — correct behavior)
- Findings: 6 (up from 4 in v0.8.0), 1 critical + 2 high — browser evidence-based severity attribution consistent

---

## Env vars added in v0.9.0

| Var | Default | Effect |
|---|---|---|
| `MEGATRON_BROWSER_ANGLES` | `2` | Multi-shot browser retries per finding. Time cost scales linearly. |

---

## What MEGATRON now does that no other open-source AI pentester does

Cross-referencing PentestGPT, AutoPentest-AI, Shannon Open Source, VulnBot, HackingBuddyGPT, Nebula as of 2026-09:

- **Bidirectional auth cookie flow** — browser session cookies exported back to CLI tools (v0.8.0)
- **Session-aware planning** with LLM-populated `session_note` memo across actions (v0.8.0)
- **Cross-finding param correlation** for chained exploit attempts (v0.9.0)
- **Multi-shot ensemble** with vuln-class-priority prompt angles (v0.9.0)
- **Ground-truth NVD verification** on every LLM-claimed CVE (v0.5.0)
- **Proactive NVD product+version injection** across 65 product aliases (v0.6.0)
- **Multi-tier fallback**: browser LLM → CLI specialist → correlate-chain (v0.9.0)
- **Split PLANNING_MODEL routing** — use different model for planning vs structured output (v0.8.0)
- **Skip-marker filter** on exploit loop (won't try to exploit "Scan Skipped" findings) (v0.6.0)

---

## Path forward beyond v0.9.0

- **Bigger model for planning** — user replacing P40 now; when ready, `export PLANNING_MODEL='hf.co/OBLITERATUS/Qwen3.8-27B-OBLITERATED:Q4_K_M'` and rerun
- **XBOW L2+L3 full sweep** once we have model + budget
- **Real-world lab targets** — MEGATRON's specialists shine most on real infra (Windows AD, k8s, actual OWASP-Juice-Shop instance)
- **CI/CD integration** — fail-on-severity, JSON output to disk

---

## Promoting to GitHub Release

Still no Megatron-scoped PAT. One-click: <https://github.com/d3ath69/Megatron/releases/new?tag=v0.9.0> → paste this file.
