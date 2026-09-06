# MEGATRON on Docker

Quickstart: one `docker compose up` and you're scanning. This doc explains what happens under the hood + how to plug in Ollama on the host + GPU passthrough.

---

## Prerequisites (on the host, not in the container)

- **Docker Engine 20.10+** and **Docker Compose v2** (`docker compose ...`, no dash)
- **Ollama** installed on the host with at least one model pulled:
  ```bash
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M   # default since v0.5.2 — 114 tok/s, uncensored, Claude-fine-tuned
  # or the safer/older default:
  ollama pull qwen2.5:7b-instruct                                          # 35 tok/s, more predictable
  ```
- **NVIDIA GPU** (recommended) — Ollama uses it automatically once the NVIDIA driver is installed on the host. **You do not need `nvidia-container-toolkit`** because Ollama runs on the host, not in the container.
- **Ports free**: MEGATRON's container publishes nothing by default. Ollama uses `11434` on the host.

---

## Fastest path (dev / lab)

```bash
git clone git@github.com:d3ath69/Megatron.git
cd Megatron
docker compose up -d --build     # first build takes ~10-15min (downloads all tools)
docker compose exec megatron python3 megatron.py
```

Menu → `1` → target → `p` → done. Scan history persists in the `megatron-db` volume across restarts.

To stop: `docker compose down`. To wipe everything including scan history: `docker compose down -v`.

---

## What the compose stack contains

```
┌─────────────────────────────────────────────────────────────────┐
│  HOST (your box)                                                 │
│  ┌────────────────────────────┐                                  │
│  │  Ollama :11434             │                                  │
│  │  qwen2.5:7b-instruct       │  <── reached from container      │
│  │  (uses NVIDIA GPU directly)│      via host.docker.internal    │
│  └────────────────────────────┘                                  │
│                                                                  │
│  Docker network: megatron-net                                    │
│  ┌─────────────────────┐    ┌──────────────────────────────┐    │
│  │  megatron           │───▶│  mariadb (megatron-mariadb)  │    │
│  │  All 20+ tools      │    │  Schema auto-loaded from     │    │
│  │  Ollama client      │    │  docs/schema.sql on 1st boot │    │
│  │  Pydantic pipeline  │    │  Data → megatron-db volume   │    │
│  └─────────────────────┘    └──────────────────────────────┘    │
│         │  reports/, exports/, scans/ bind-mounted to ./         │
└─────────────────────────────────────────────────────────────────┘
```

**Why Ollama on host, not in container:**
1. GPU access without `nvidia-container-toolkit` (fewer moving parts)
2. Model download is one-time; the host cache is reused across container rebuilds
3. Ollama's memory-mapped model files perform better outside the container storage driver

---

## Config knobs (env vars)

All env vars have sensible lab defaults. Override in a `.env` file next to `docker-compose.yml` or export before `docker compose up`:

| Var | Default | Effect |
|---|---|---|
| `OLLAMA_HOST` | `http://host.docker.internal:11434` | Where the container reaches Ollama. Change if Ollama is on a different LAN box. |
| `MODEL_NAME` | `hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M` | Any Ollama-visible tag. See "Model swap" below. |
| `MODEL_TEMPERATURE` | `0.5` | 0.1 for `qwen2.5:7b-instruct` (deterministic). 0.5 for Qwythos (their docs warn T≤0.3 causes repetition loops). |
| `MODEL_THINK` | `false` | Ollama `think` param. Set `true` only for reasoning models that explicitly need chain-of-thought. |
| `OLLAMA_TIMEOUT` | `600` | Bump to `1200` if using 27B models or the exploit-execution loop times out on hard targets. |
| `MEGATRON_MAX_LOOPS` | `6` | Cap on ReAct dispatch rounds (LLM tool-call ping-pongs). |
| `PLANNING_MODEL` | *(same as MODEL_NAME)* | v0.8.0: browser-loop planning model. Set to a bigger model (e.g., 27B) for better CSS selector picking. |
| `MEGATRON_BROWSER_MAX_ACTIONS` | `15` | v0.8.0: browser exploit-loop action ceiling. Lower = faster scans, higher = deeper chains. |
| `MEGATRON_BROWSER_ANGLES` | `2` | v0.9.0: multi-shot ensemble — retry browser exploit with N different prompt angles per finding. Total time scales roughly linearly. |
| `MEGATRON_BOOTSTRAP_USER` / `_PASS` / `_EMAIL` | `megatron_test_user` / `M3g4tr0n!Test123` / `megatron@example.test` | v0.8.0: creds used by browser_agent.bootstrap_auth() to auto-register+login before exploit loop. Successful login exports cookies back to `AUTH_COOKIE`. |
| `AUTH_COOKIE` | *(unset)* | e.g. `sessionid=abc123; csrftoken=xyz` — threaded through httpx / nuclei / katana / feroxbuster / dalfox / flag-hunt for authenticated scans. |
| `AUTH_HEADER` | *(unset)* | e.g. `Authorization: Bearer eyJhbGci...` — same threading. |
| `NVD_API_KEY` | *(unset)* | Free at nvd.nist.gov — lifts NVD rate limit from 5→50 req/30s. |
| `DB_HOST` | `mariadb` | Container hostname of the DB service (compose network). |
| `DB_USER` / `DB_PASSWORD` / `DB_NAME` | `megatron` / `123` / `megatron` | Change for anything past lab use. |

Example `.env` for the qwen2.5-instruct fallback (if Qwythos gives you trouble):
```env
MODEL_NAME=qwen2.5:7b-instruct
MODEL_TEMPERATURE=0.1
MODEL_THINK=false
```

Example `.env` for scanning a logged-in app (both cookie AND custom header):
```env
AUTH_COOKIE=sessionid=abc123; csrftoken=xyz789
AUTH_HEADER=X-API-Key: sk_live_...
```

Then `docker compose up -d && docker compose exec megatron python3 megatron.py`.

---

## Networking modes

**Default (bridge network):**
- Container has its own IP inside the `megatron-net` bridge
- Scans go out through Docker NAT (source IP = your host's IP)
- Works for internet targets and LAN targets
- Cannot scan `127.0.0.1` = the host's loopback (that's the *container's* loopback, empty)

**If you need to scan the host itself** (e.g., `127.0.0.1` for a locally-running vuln app), the cleanest option is to run megatron with `--network=host`:

```bash
docker run --rm -it --network=host \
  -e OLLAMA_HOST=http://127.0.0.1:11434 \
  -e DB_HOST=127.0.0.1 \
  --entrypoint python3 \
  megatron:latest megatron.py
```

Note: `--network=host` disables the `mariadb` service link — DB must be reachable at `127.0.0.1:3306` (either bare-metal MariaDB on the host or `docker run mariadb -p 3306:3306`).

---

## GPU access (optional — only if you want Ollama INSIDE the container)

Skip this unless you have a good reason. The default host-Ollama setup is simpler and works with the same GPU.

If you insist:
1. Install `nvidia-container-toolkit` on the host
2. Add `deploy: resources: reservations: devices: - driver: nvidia, capabilities: [gpu]` to the `megatron` service
3. Uncomment the Ollama sidecar service (not shipped by default — add manually)

---

## Rebuilding

```bash
# Code change to any .py file → rebuild:
docker compose build megatron && docker compose up -d megatron

# Tools got a new release upstream → force clean rebuild:
docker compose build --no-cache megatron

# Reset DB (lose all scan history):
docker compose down -v && docker compose up -d
```

---

## Volumes explained

- **`megatron-db`** (named volume): persistent MariaDB data
- **`./reports/`** (bind mount): PDF report exports from the menu
- **`./exports/`** (bind mount): HTML report exports
- **`./scans/`** (bind mount): raw JSON scan artifacts

Anything you want to keep after `docker compose down -v` should go under `./reports`, `./exports`, or `./scans`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Cannot connect to Ollama` inside container | Verify `ollama serve` running on host: `curl http://localhost:11434/api/tags`. Also confirm `host.docker.internal` resolves in the container: `docker compose exec megatron getent hosts host.docker.internal` |
| Scan output empty / all tools "not found" | Rebuild without cache: `docker compose build --no-cache megatron`. Some tool releases (dalfox v3.2.2 in particular) have naming quirks that occasionally shift. |
| MariaDB won't accept connections | `docker compose logs mariadb`. First boot takes ~10s for schema init. If persistent: `docker compose down -v` and let it re-init. |
| `nmap` scans get ECONNREFUSED on hosts you know are up | You're on bridge network. See "networking modes" above and use `--network=host`. |
| Model runs slow (2-5 tok/s) | GPU not visible to Ollama. On host: `nvidia-smi`. Also check `ollama ps` shows `size_vram > 0`. |

---

## Sizes on disk

- MEGATRON container image (built): **~2.4 GB** (Ubuntu base + Python + all 20+ tools + SecLists 2.5GB — bulk is SecLists wordlists)
- MariaDB container image: 400 MB
- MariaDB data volume: starts ~250 MB, grows with scan history
- Ollama model on host: 4.7 GB (qwen2.5:7b) or 5.6 GB (Qwythos-9B Q4_K_M)

Total footprint ≈ 7-10 GB depending on model.
