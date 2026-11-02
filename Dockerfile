FROM debian:bookworm-slim AS pd-tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/n.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip && unzip -oq /tmp/n.zip nuclei -d /usr/local/bin
RUN curl -fsSL -o /tmp/k.zip https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana_1.8.0_linux_amd64.zip && unzip -oq /tmp/k.zip katana -d /usr/local/bin
RUN curl -fsSL -o /tmp/h.zip https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip && unzip -oq /tmp/h.zip httpx -d /usr/local/bin
RUN curl -fsSL -o /tmp/g.tar.gz https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz && tar -xzf /tmp/g.tar.gz -C /usr/local/bin gau
RUN curl -fsSL -o /tmp/f.tar.gz https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz && tar -xzf /tmp/f.tar.gz -C /usr/local/bin ffuf
RUN curl -fsSL -o /tmp/d.tar.gz https://github.com/hahwul/dalfox/releases/download/v3.2.4/dalfox-v3.2.4-linux-x86_64-musl.tar.gz && mkdir -p /tmp/dalfox-package && tar -xzf /tmp/d.tar.gz -C /tmp/dalfox-package && DALFOX_BIN="$(find /tmp/dalfox-package -type f -name 'dalfox*' | head -n 1)" && test -n "$DALFOX_BIN" && install -m 0755 "$DALFOX_BIN" /usr/local/bin/dalfox
RUN curl -fsSL -o /tmp/s.tar.gz https://github.com/sqlmapproject/sqlmap/archive/refs/tags/1.10.tar.gz && mkdir -p /opt/sqlmap && tar -xzf /tmp/s.tar.gz -C /opt/sqlmap --strip-components=1
RUN curl -fsSL -o /tmp/nikto.tar.gz https://github.com/sullo/nikto/archive/refs/tags/2.6.1.tar.gz && mkdir -p /opt/nikto && tar -xzf /tmp/nikto.tar.gz -C /opt/nikto --strip-components=1
RUN curl -fsSL -o /tmp/testssl.tar.gz https://github.com/testssl/testssl.sh/archive/refs/tags/v3.2.4.tar.gz && mkdir -p /opt/testssl && tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1

FROM ruby:3.3.13-slim-bookworm AS wp-tools
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libcurl4-openssl-dev libffi-dev libyaml-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
RUN gem install wpscan -v 4.2.0 --no-document
# Metadata is fetched during the remote image build, never during a target scan.
RUN wpscan --update

FROM zaproxy/zap-stable
USER root
COPY --from=wp-tools /usr/local/ /usr/local/
COPY --from=wp-tools /root/.cache/wpscan/db /opt/wpscan-db
COPY --from=pd-tools /opt/nikto /opt/nikto
COPY --from=pd-tools /opt/testssl /opt/testssl
COPY --from=pd-tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=pd-tools /usr/local/bin/katana /usr/local/bin/katana
COPY --from=pd-tools /usr/local/bin/httpx /usr/local/bin/pd-httpx
COPY --from=pd-tools /usr/local/bin/gau /usr/local/bin/gau
COPY --from=pd-tools /usr/local/bin/ffuf /usr/local/bin/ffuf
COPY --from=pd-tools /usr/local/bin/dalfox /usr/local/bin/dalfox
COPY --from=pd-tools /opt/sqlmap /opt/sqlmap
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv python3-pip perl libxml-writer-perl libxml-libxml-perl libjson-perl libnet-ssleay-perl libio-socket-ssl-perl openssl libcurl4 libyaml-0-2 libgmp10 libffi8 libgdbm6 libgdbm-compat4 libreadline8 zlib1g procps dnsutils coreutils && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/asfb-venv && /opt/asfb-venv/bin/pip install --no-cache-dir fastapi==0.115.12 uvicorn==0.34.2 python-multipart==0.0.20 httpx==0.28.1 arjun==2.2.7 PyYAML==6.0.2
WORKDIR /app
COPY --chown=zap:zap app /app/app
RUN test -s /app/app/nuclei-templates/technology-headers.yaml
COPY --chown=zap:zap start.sh /app/start.sh
RUN chmod +x /app/start.sh && mkdir -p /app/data /home/zap/.cache/wpscan && cp -a /opt/wpscan-db /home/zap/.cache/wpscan/db && chown -R zap:zap /app/data /home/zap/.cache/wpscan && ldconfig
USER zap
ENV GEM_HOME="/usr/local/bundle"
ENV PATH="/opt/asfb-venv/bin:/usr/local/bundle/bin:$PATH" PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["/app/start.sh"]
