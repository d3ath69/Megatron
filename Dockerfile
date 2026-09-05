FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ENV PATH=/opt/megatron/venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    OLLAMA_HOST=http://host.docker.internal:11434 \
    MODEL_NAME=qwen2.5:7b-instruct \
    DB_HOST=mariadb \
    DB_PORT=3306 \
    DB_USER=megatron \
    DB_PASSWORD=123 \
    DB_NAME=megatron

RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common ca-certificates curl wget gnupg \
        python3 python3-venv python3-pip python3-dev build-essential \
        git unzip openssl \
    && add-apt-repository -y universe \
    && apt-get update && apt-get install -y --no-install-recommends \
        nmap whois whatweb dnsutils nikto \
        default-mysql-client \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/pd-installs

RUN set -eux; \
    for name in naabu subfinder katana; do \
      URL=$(curl -sL "https://api.github.com/repos/projectdiscovery/${name}/releases/latest" \
            | grep browser_download_url | grep linux_amd64.zip | grep -v arm | head -1 | cut -d'"' -f4); \
      curl -sL -o "${name}.zip" "$URL"; \
      unzip -q -o "${name}.zip"; \
      install -m 0755 "${name}" /usr/local/bin/; \
    done; \
    URL=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
          | grep browser_download_url | grep linux_amd64.zip | grep -v arm | head -1 | cut -d'"' -f4); \
    curl -sL -o httpx.zip "$URL"; unzip -q -o httpx.zip; \
    install -m 0755 httpx /usr/local/bin/httpx-pd; \
    URL=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
          | grep browser_download_url | grep linux_amd64.zip | grep -v arm | head -1 | cut -d'"' -f4); \
    curl -sL -o nuclei.zip "$URL"; unzip -q -o nuclei.zip; \
    install -m 0755 nuclei /usr/local/bin/; \
    nuclei -update-templates -silent || true

RUN set -eux; \
    curl -sL -o dalfox.deb "https://github.com/hahwul/dalfox/releases/download/v3.2.2/dalfox-v3.2.2-linux-x86_64.deb"; \
    apt-get install -y --no-install-recommends ./dalfox.deb; \
    rm dalfox.deb; \
    curl -sL -o ferox.zip "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip"; \
    unzip -q -o ferox.zip; install -m 0755 feroxbuster /usr/local/bin/; \
    for pd in trufflesecurity/trufflehog dwisiswant0/crlfuzz sensepost/gowitness; do \
      base=$(basename "$pd"); \
      URL=$(curl -sL "https://api.github.com/repos/${pd}/releases/latest" \
            | grep browser_download_url \
            | grep -iE "linux.*(amd64|x86_64)" \
            | grep -v arm | grep -viE "sha|sig" | head -1 | cut -d'"' -f4); \
      curl -sL -o "${base}_pkg" "$URL"; \
      case "$URL" in \
        *.tar.gz|*.tgz) tar -xzf "${base}_pkg"; install -m 0755 "$base" /usr/local/bin/;; \
        *.zip)          unzip -q -o "${base}_pkg"; install -m 0755 "$base" /usr/local/bin/;; \
        *)              chmod +x "${base}_pkg"; install -m 0755 "${base}_pkg" "/usr/local/bin/${base}";; \
      esac; \
    done; \
    apt-get clean && rm -rf /var/lib/apt/lists/* /opt/pd-installs/*

RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && sed -i '1s|env python|env python3|' /opt/commix/commix.py \
    && chmod +x /opt/commix/commix.py \
    && ln -sf /opt/commix/commix.py /usr/local/bin/commix \
    && git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/SSTImap \
    && chmod +x /opt/SSTImap/sstimap.py \
    && ln -sf /opt/SSTImap/sstimap.py /usr/local/bin/sstimap \
    && git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /opt/SSRFmap \
    && git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists

WORKDIR /opt/megatron

COPY requirements.txt ./
RUN python3 -m venv venv \
    && ./venv/bin/pip install --upgrade pip \
    && ./venv/bin/pip install --no-cache-dir -r requirements.txt \
    && ./venv/bin/pip install --no-cache-dir sqlmap sstimap schemathesis semgrep

COPY . .

RUN sed -i 's|_SSRFMAP_PATH   = "/home/d3ath/SSRFmap/ssrfmap.py"|_SSRFMAP_PATH   = "/opt/SSRFmap/ssrfmap.py"|' tools.py

VOLUME ["/opt/megatron/reports", "/opt/megatron/exports"]

CMD ["python3", "megatron.py"]
