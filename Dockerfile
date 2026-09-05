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
    curl -sL -o naabu.zip     "https://github.com/projectdiscovery/naabu/releases/download/v2.6.1/naabu_2.6.1_linux_amd64.zip"; \
    unzip -q -o naabu.zip;     install -m 0755 naabu     /usr/local/bin/; \
    curl -sL -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_linux_amd64.zip"; \
    unzip -q -o subfinder.zip; install -m 0755 subfinder /usr/local/bin/; \
    curl -sL -o katana.zip    "https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_amd64.zip"; \
    unzip -q -o katana.zip;    install -m 0755 katana    /usr/local/bin/; \
    curl -sL -o httpx.zip     "https://github.com/projectdiscovery/httpx/releases/download/v1.10.0/httpx_1.10.0_linux_amd64.zip"; \
    unzip -q -o httpx.zip;     install -m 0755 httpx     /usr/local/bin/httpx-pd; \
    curl -sL -o nuclei.zip    "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip"; \
    unzip -q -o nuclei.zip;    install -m 0755 nuclei    /usr/local/bin/; \
    nuclei -update-templates -silent || true

RUN set -eux; \
    curl -sL -o dalfox.deb "https://github.com/hahwul/dalfox/releases/download/v3.2.2/dalfox-v3.2.2-linux-x86_64.deb"; \
    apt-get install -y --no-install-recommends ./dalfox.deb; \
    rm dalfox.deb; \
    curl -sL -o ferox.zip "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip"; \
    unzip -q -o ferox.zip; install -m 0755 feroxbuster /usr/local/bin/; \
    curl -sL -o trufflehog.tgz "https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.4/trufflehog_3.97.4_linux_amd64.tar.gz"; \
    tar -xzf trufflehog.tgz; install -m 0755 trufflehog /usr/local/bin/; \
    curl -sL -o crlfuzz.tgz "https://github.com/dwisiswant0/crlfuzz/releases/download/v1.4.1/crlfuzz_1.4.1_linux_amd64.tar.gz"; \
    tar -xzf crlfuzz.tgz; install -m 0755 crlfuzz /usr/local/bin/; \
    curl -sL -o gowitness "https://github.com/sensepost/gowitness/releases/download/3.1.1/gowitness-3.1.1-linux-amd64"; \
    chmod +x gowitness; install -m 0755 gowitness /usr/local/bin/gowitness; \
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
