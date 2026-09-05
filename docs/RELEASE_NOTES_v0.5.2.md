# MEGATRON v0.5.2 — Qwythos-9B default + port-backfill guarantee + XBOW baseline

**Released 2026-09-05.** [Commit history](https://github.com/d3ath69/Megatron/commits/main) · [Full CHANGELOG](../CHANGELOG.md)

---

## The 4 things that changed

### 1. Default model swapped to Qwythos-9B (3× faster + uncensored + Claude-fine-tuned)

`MODEL_NAME` default is now `hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M`. `MODEL_TEMPERATURE` bumped to `0.5` (their docs warn `T ≤ 0.3` triggers repetition loops in reasoning-model post-training).

Benchmark on RTX 3070 (both models on MEGATRON's structured-output pipeline):

| Model | tok/s | Findings on synthetic scan | Notes |
|---|---|---|---|
| qwen2.5:7b-instruct (old default) | 35 | 12 (all NVD-injected) | Generic instruction-tuned |
| **Qwythos-9B-Claude-Mythos-5-1M** | **114** | 16 (4 LLM-named CVEs + 12 NVD-injected) | Uncensored, cybersecurity-tagged, native fn-calling |

To revert if needed (both models are ollama-pullable):
```bash
export MODEL_NAME='qwen2.5:7b-instruct' MODEL_TEMPERATURE=0.1
```

### 2. Port + service fields now guaranteed on every finding (`_fill_missing_ports()`)

Previous versions: LLM-generated findings left `port` and `service` empty because both qwen2.5 and Qwythos habitually ignore that instruction. NVD-injected findings always had them (populated by our injection code).

Now: after post-validation, a code-side fallback cross-references every empty-port finding against `_extract_service_versions(raw_scan)` and backfills from the recon evidence. Match order: exact service token → product alias → common aliases (`openssh→ssh`, `http_server→apache`).

Sample output from the v0.5.2 verification run:
```
  [medium  ] OpenSSH 8.9p1 Terrapin Attack (CVE-2023-48795)  port=22   ← was port=  in v0.5.1
  [critical] Apache httpd 2.4.49 RCE (CVE-2024-47147)         port=80   ← was port=  in v0.5.1
  [critical] Jetty Default Admin Panel                        port=8080 ← was port=  in v0.5.1
  [critical] MySQL 5.5.62 Default Root Password               port=3306 ← was port=  in v0.5.1
```

### 3. XBOW baseline harness rewritten to match real XBOW structure

v0.5.1's `xbow_bench.py` assumed a `web` service and `docker compose port` conventions — neither correct. Rewrote to:

- Use XBOW's canonical `make -C benchmarks/NAME {build,run,stop}` flow (respects their common.mk)
- Compute the deterministic flag `FLAG{sha256(BENCHMARK_NAME_UPPER)}`
- Discover exposed ports dynamically via `docker compose ps --format json`
- Prefer web ports (80/8080/8443/3000/5000) but fall back to any published port

Baseline results (see [next section](#xbow-baseline-5-challenges)).

### 4. GitHub release + tag `v0.5.2`

First real semantic-versioned tag on the repo. Download the release tarball or check out the tag:
```bash
git clone --branch v0.5.2 git@github.com:d3ath69/Megatron.git
```

---

## XBOW baseline (5 challenges)

Ran against 5 Level-1 (easiest) challenges covering the canonical web vuln categories:

| Challenge | Category | Result (see [xbow-results.jsonl](../scripts/xbow-results.jsonl)) |
|---|---|---|
| XBEN-005-24 | IDOR + JWT + default_credentials | (pending) |
| XBEN-006-24 | SQLi with allowlist | (pending) |
| XBEN-009-24 | SSTI (Django) | (pending) |
| XBEN-013-24 | XSS | (pending) |
| XBEN-019-24 | LFI + information_disclosure | (pending) |

**Reference SOTA**: [Shannon](https://github.com/KeygraphHQ/shannon) hit 96.15% on the full 104-challenge suite (source-aware, white-box). MEGATRON is currently **black-box only** and does **recon + LLM-analysis** without a full exploitation loop, so baseline flag-capture is expected to be low (Tier 3 browser-automation is the roadmap item that closes this gap).

The value of this baseline isn't the raw score — it's establishing a measurable trajectory over time.

To re-run yourself:
```bash
cd ~/Megatron && source venv/bin/activate
python3 scripts/xbow_bench.py --clone
python3 scripts/xbow_bench.py --run-many XBEN-005-24,XBEN-006-24,XBEN-009-24,XBEN-013-24,XBEN-019-24
python3 scripts/xbow_bench.py --score
```

---

## Upgrade from v0.5.1

```bash
git pull origin main
# One-time: pull the new default model
ollama pull hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M
# If using Docker:
docker compose build --no-cache && docker compose up -d
```

That's it. All existing DB rows, wordlists, tools, and scans are preserved.

---

## Known limitations (unchanged from v0.5.1)

- **Black-box only.** MEGATRON scans + reasons; it doesn't drive a browser to execute exploits and prove them (Shannon-style "No Exploit, No Report"). Tier 3 Playwright wrapper is the substrate; full exploitation-loop is roadmap.
- **NVD API rate-limited to 5 req/30s** without an NVD API key. For large multi-service scans, the CVE-injection phase can add 30-60s. Get a free NVD key + export `NVD_API_KEY` to lift this.
- **SecLists is 2.5GB** — the Docker image is 2.28GB largely because of it. Bulk is wordlists, not code.

---

## Contributor notes

If you're adding a new tool wrapper:
1. Wrapper in `tools.py` — follow the pattern (typed args, `subprocess` via `run_tool()`, print announcement, return combined stdout+stderr)
2. Add to `TOOLS_MENU` with a single-letter menu key
3. Add binary name to `ALLOWED_TOOLS` for LLM `[TOOL:...]` dispatch
4. If the tool has a JSON output mode, prefer it (LLM ingestion is far more reliable)
5. If it needs a pinned version, add to the Dockerfile's specialist-tools layer with explicit URL (no `/latest` API calls — GitHub anonymous rate limit is 60/h)
