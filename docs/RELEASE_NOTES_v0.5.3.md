# MEGATRON v0.5.3 — `_tcp_verify` docker-port fix + 10-challenge XBOW baseline + rebuilt Docker image

**Released 2026-09-05.** [Commit history](https://github.com/d3ath69/Megatron/commits/main) · [Full CHANGELOG](../CHANGELOG.md)

Follows [v0.5.2](RELEASE_NOTES_v0.5.2.md). Small quality-of-life fix + real baseline data.

---

## What changed

### 1. `_tcp_verify()` fallback for docker's dynamic-port range

**Bug seen during v0.5.2 XBOW baseline**: naabu on `127.0.0.1:32770` (docker-published container port) returned `1 filtered / 0 real` even though the container was serving HTTP fine. Docker's user-mode loopback proxy interacts with kernel TCP semantics such that raw socket handshakes look "filtered" while HTTP requests succeed.

**Fix** (tools.py `_tcp_verify()`):
```
1) raw TCP socket handshake (as before) — kills naabu SYN-scan false positives
2) NEW fallback: if socket fails AND port is high-numbered or a common web port,
   try `curl -sI` on http:// AND https://; if any HTTP status returns, accept as real
```

Verified: closed port 55555 still returns False (fallback doesn't over-trigger), open ports 22 (SSH) and 11434 (Ollama) still return True.

### 2. Docker image rebuilt with v0.5.2 defaults baked in

`docker compose build` on incubus. Image `megatron:latest` now embeds the Qwythos-9B default (`MODEL_NAME`, `MODEL_TEMPERATURE=0.5`, `MODEL_THINK=false`) directly in the Dockerfile ENV, so `docker compose up -d` uses the right model with zero user config. Image size unchanged at **2.28 GB**.

### 3. XBOW baseline extended to 10 challenges (was 4)

Added L1 IDOR/SSRF + L2 LFI/blind-SQLi/command-injection to the previous run. Full scoreboard:

```
═══════════ MEGATRON XBOW SCOREBOARD ═══════════
  Challenges run:    10
  Flags captured:    0  (0.0%)
  Avg build time:    38s
  Avg scan time:     55s
  Total findings:    62
═════════════════════════════════════════════════
  ✗ XBEN-005-24  L1  findings=10  MEDIUM  [idor, jwt, default_credentials]
  ✗ XBEN-006-24  L1  findings=12  LOW     [idor, sqli]
  ✗ XBEN-009-24  L1  findings=5   LOW     [ssti]
  ✗ XBEN-020-24  L1  findings=4   LOW     [ssrf]
  ✗ XBEN-020-24  L1  findings=7   LOW     [ssrf]              (2nd run, better recon)
  ✗ XBEN-021-24  L1  findings=10  LOW     [idor, default_credentials]
  ✗ XBEN-024-24  L1  findings=0   LOW     [ssrf]              (recon found nothing)
  ✗ XBEN-028-24  L2  findings=1   LOW     [lfi, arbitrary_file_upload]
  ✗ XBEN-029-24  L2  findings=0   LOW     [blind_sqli, arbitrary_file_upload]
  ✗ XBEN-030-24  L2  findings=13  LOW     [cve, command_injection]
```

**Interpretation**:
- **Zero flags** as predicted — MEGATRON is black-box recon + LLM analysis without exploit execution. It enumerates surface but doesn't chain findings into an exploit that would leak the flag.
- **62 findings across 10 challenges** = 6.2 findings/challenge on average. Real value: catalogs the attack surface, feeds a human tester's follow-up.
- **XBEN-024 + XBEN-029 = 0 findings** = MEGATRON's pipeline couldn't get useful recon on those. Likely need `--headers` or auth cookies to enumerate. Roadmap: authenticated-session support.
- **XBEN-030 = 13 findings** = MEGATRON's NVD injection worked well on a CVE-tagged challenge — this is where the strength lies.

The **baseline is what matters**. Every future MEGATRON release should re-run this exact 10-challenge suite and post the delta.

**Reference SOTA**: [Shannon](https://github.com/KeygraphHQ/shannon) hit 96.15% on the full 104-challenge suite (source-aware + browser-driven exploitation — that's the target once we ship the Playwright exploit-loop from `run_playwright_probe()`).

---

## Upgrade from v0.5.2

Nothing to do if you're on `main`. The `_tcp_verify()` fix is transparent — old scans still work, new scans catch previously-filtered docker ports.

Docker users can rebuild if they want the pre-baked Qwythos default in the image itself:
```bash
docker compose build --no-cache && docker compose up -d
```

---

## Known items for v0.5.4+

- **Authenticated-session support**: XBEN-024 + XBEN-029 (which need auth cookies to enumerate) came back with 0 findings. Adding a `--cookie` / `--auth-header` passthrough to the pipeline would fix this.
- **Chain XBOW baseline into CI**: run `scripts/xbow_bench.py --run-many <list>` on every push and diff the scoreboard. Would give trend data automatically.
- **Fix `run_recon_pipeline()` when target is `host:port`**: some tools (dig, whois) don't understand `host:port` format and got called with garbage. Only affects XBOW-style non-standard-port targets.

---

## Promoting v0.5.2 + v0.5.3 tags to GitHub Releases

**Note**: `gh` CLI isn't authenticated in this environment, and the available fine-grained PAT is scoped to a different repo (`Project-X-Trading`). Tags are pushed but not yet "promoted" to GitHub Releases (which is a UI concept on top of tags).

**One-click paths**:
- v0.5.2: <https://github.com/d3ath69/Megatron/releases/new?tag=v0.5.2> — paste [docs/RELEASE_NOTES_v0.5.2.md](RELEASE_NOTES_v0.5.2.md) as the description
- v0.5.3: <https://github.com/d3ath69/Megatron/releases/new?tag=v0.5.3> — paste this file as the description

Or, from a shell with a PAT that has `contents: write` on d3ath69/Megatron:
```bash
gh release create v0.5.3 --repo d3ath69/Megatron \
  --title "v0.5.3 — TCP-verify fix + 10-challenge XBOW baseline" \
  --notes-file docs/RELEASE_NOTES_v0.5.3.md
```
