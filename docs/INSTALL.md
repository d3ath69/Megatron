# MEGATRON install guide

Two supported paths:

- **[Docker](DOCKER.md)** — one `docker compose up`, ~10 min first build, everything self-contained (recommended).
- **Bare metal** — Ubuntu 24.04 / Parrot OS. Below. Longer, more moving parts, but no container overhead.

---

## Bare-metal install (Ubuntu 24.04 / Parrot OS)

### 1. Clone

```bash
git clone git@github.com:d3ath69/Megatron.git ~/Megatron
cd ~/Megatron
```

### 2. Python + venv + Pydantic/Ollama deps

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip build-essential
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install sqlmap sstimap schemathesis semgrep
```

### 3. System recon tools (apt, universe repo required on Ubuntu 24.04)

```bash
sudo add-apt-repository -y universe
sudo apt update
sudo apt install -y nmap whois whatweb curl dnsutils nikto \
                    openssl unzip mariadb-server mariadb-client git
```

### 4. SecLists wordlists (~2.5 GB, needed by feroxbuster + ffuf)

```bash
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists
```

### 5. ProjectDiscovery binaries (naabu / httpx / nuclei / subfinder / katana)

```bash
mkdir -p /tmp/pd && cd /tmp/pd
for name in naabu subfinder katana; do
  URL=$(curl -sL "https://api.github.com/repos/projectdiscovery/${name}/releases/latest" \
        | grep browser_download_url | grep linux_amd64.zip | grep -v arm | head -1 | cut -d'"' -f4)
  curl -sL -o ${name}.zip "$URL"
  unzip -o ${name}.zip
  sudo install -m0755 ${name} /usr/local/bin/
done

# httpx (installed as `httpx-pd` to avoid Python `httpx` CLI conflict)
URL=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
      | grep browser_download_url | grep linux_amd64.zip | grep -v arm | head -1 | cut -d'"' -f4)
curl -sL -o httpx.zip "$URL" && unzip -o httpx.zip
sudo install -m0755 httpx /usr/local/bin/httpx-pd

# nuclei + 13k community templates
URL=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | grep browser_download_url | grep linux_amd64.zip | grep -v arm | head -1 | cut -d'"' -f4)
curl -sL -o nuclei.zip "$URL" && unzip -o nuclei.zip
sudo install -m0755 nuclei /usr/local/bin/
nuclei -update-templates
```

### 6. Specialist scanners (dalfox / feroxbuster / trufflehog / crlfuzz / gowitness)

```bash
# dalfox — .deb from GitHub release (dashes in name, not underscores)
curl -sL -o /tmp/dalfox.deb "https://github.com/hahwul/dalfox/releases/download/v3.2.2/dalfox-v3.2.2-linux-x86_64.deb"
sudo dpkg -i /tmp/dalfox.deb && rm /tmp/dalfox.deb

# feroxbuster — official `latest` alias works
curl -sL -o /tmp/ferox.zip \
  "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip"
cd /tmp && unzip -o ferox.zip
sudo install -m0755 feroxbuster /usr/local/bin/

# trufflehog / crlfuzz / gowitness — helper loop
for pd in trufflesecurity/trufflehog dwisiswant0/crlfuzz sensepost/gowitness; do
  base=$(basename "$pd")
  URL=$(curl -sL "https://api.github.com/repos/${pd}/releases/latest" \
        | grep browser_download_url \
        | grep -iE "linux.*(amd64|x86_64)" \
        | grep -v arm | grep -viE "sha|sig" | head -1 | cut -d'"' -f4)
  curl -sL -o "/tmp/${base}_pkg" "$URL"
  cd /tmp
  case "$URL" in
    *.tar.gz|*.tgz) tar -xzf ${base}_pkg; sudo install -m0755 $base /usr/local/bin/;;
    *.zip)          unzip -o ${base}_pkg; sudo install -m0755 $base /usr/local/bin/;;
    *)              chmod +x ${base}_pkg; sudo install -m0755 ${base}_pkg /usr/local/bin/$base;;
  esac
done
```

### 7. Non-releasable clones (commix, sstimap, SSRFmap)

```bash
# commix — Ubuntu 24.04 has `python3` not `python`, so patch the shebang
sudo git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix
sudo sed -i '1s|env python|env python3|' /opt/commix/commix.py
sudo chmod +x /opt/commix/commix.py
sudo ln -sf /opt/commix/commix.py /usr/local/bin/commix

# SSTImap
sudo git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/SSTImap
sudo chmod +x /opt/SSTImap/sstimap.py
sudo ln -sf /opt/SSTImap/sstimap.py /usr/local/bin/sstimap

# SSRFmap (per-user clone — tools.py points at ~/SSRFmap by default; adjust if you move it)
git clone https://github.com/swisskyrepo/SSRFmap.git ~/SSRFmap
```

### 8. MariaDB — create the `megatron` database + user + tables

```bash
sudo systemctl enable --now mariadb
sudo mariadb < docs/schema.sql
# verify:
mysql -u megatron -p123 megatron -e "SHOW TABLES;"
```

### 9. Ollama + model

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b-instruct

# Optional: alternative model (uncensored, Claude-fine-tuned, 9B — needs MODEL_TEMPERATURE=0.5 + MODEL_THINK=true)
ollama pull hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M
```

### 10. Run it

```bash
cd ~/Megatron && source venv/bin/activate
python megatron.py

# Menu: [1] New Scan → target → [p] MEGATRON pipeline (RECOMMENDED)
```

---

## Optional: switch to the Qwythos-9B model

Uncensored, 9B params, Claude-Mythos-fine-tuned, native function calling, 1M context, 5.63GB (fits 8GB VRAM with headroom). Trade-off: it's a *reasoning model* — every response starts with a `<think>` block, and low temperature causes repetition loops (their docs explicitly warn `T ≤ 0.3` is unsafe).

```bash
ollama pull hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M

# Then run megatron with:
export MODEL_NAME='hf.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M'
export MODEL_TEMPERATURE=0.5    # >=0.4 required by model docs; ~0.5 is a good structured-output compromise
export MODEL_THINK=true         # let Ollama render the <think> block; MEGATRON tolerates it
export OLLAMA_TIMEOUT=1200      # reasoning + 9B on RTX 3070 ≈ 15-25 tok/s, budget 20 min per full pipeline

python megatron.py
```

For CPTC prep specifically, Qwythos is the stronger pick: uncensored means it won't be conservative on exploitation content, and the Claude fine-tune improves JSON schema following. If you have 24GB VRAM (Tesla P40+), use the Q6_K or Q8_0 variant for better output quality.

---

## Post-install verification

Quick sanity check that everything imports + Ollama is reachable:

```bash
cd ~/Megatron && source venv/bin/activate
python3 -c "
import tools, llm, search, db, export
print('[+] all modules import OK')
print('    TOOLS_MENU size:', len(tools.TOOLS_MENU))
print('    ALLOWED_TOOLS size:', len(tools.ALLOWED_TOOLS))
print('    MODEL_NAME:', llm.MODEL_NAME)
print('    Ollama reachable:', bool(llm._client.list().get('models')))
print('    DB reachable:', bool(db.get_connection()))
"
```

Expected output: `TOOLS_MENU size: 27, ALLOWED_TOOLS size: 21`, Ollama + DB both `True`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `E: Unable to locate package sqlmap` | Ubuntu 24.04 doesn't include it by default | `pip install sqlmap` in your venv (step 2) |
| `env: 'python': No such file or directory` when running commix | Ubuntu 24.04 has `python3` only | `sudo sed -i '1s\|env python\|env python3\|' /opt/commix/commix.py` |
| `dalfox: command not found` after install | Release naming uses dashes (`linux-x86_64.deb`), not underscores | Use the `.deb` URL exactly as in step 6 |
| `feroxbuster: no wordlist found` | `/opt/SecLists` not cloned | Repeat step 4 |
| Naabu says port is open but nmap says filtered | Naabu SYN-scan false positive | MEGATRON handles this — `_tcp_verify()` runs a real TCP handshake and drops false positives before nmap. Check the `[naabu-verify]` log line. |
| Ollama runs at 2-3 tok/s (should be 30+) | Model spilled to CPU | `nvidia-smi` shows VRAM used. `ollama ps` shows `size_vram`. If `size_vram=0`, GPU isn't visible. Restart Ollama, verify driver. |
