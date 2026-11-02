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

RUN curl -fsSL -o /tmp/trufflehog.tgz https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.7/trufflehog_3.99.7_linux_amd64.tar.gz && tar -xzf /tmp/trufflehog.tgz -C /usr/local/bin trufflehog
RUN curl -fsSL -o /tmp/trivy.tgz https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy
RUN curl -fsSL -o /usr/local/bin/osv-scanner https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 && chmod +x /usr/local/bin/osv-scanner
RUN curl -fsSL -o /tmp/kr.tgz https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz && tar -xzf /tmp/kr.tgz -C /usr/local/bin kr
RUN curl -fsSL -o /tmp/amass.zip https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip && unzip -oq /tmp/amass.zip -d /tmp/amass && install -m 0755 /tmp/amass/amass_Linux_amd64/amass /usr/local/bin/amass

FROM ruby:3.3.13-slim-bookworm AS wp-tools
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libcurl4-openssl-dev libffi-dev libyaml-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
RUN gem install wpscan -v 4.2.0 --no-document
# Metadata is fetched during the remote image build, never during a target scan.
RUN wpscan --update

FROM node:22-bookworm-slim AS js-tools
RUN npm install --global retire@6.1.0
RUN mkdir -p /opt/retire-db && node -e "fetch('https://raw.githubusercontent.com/RetireJS/retire.js/6.1.0/repository/jsrepository-v5.json').then(r => { if (!r.ok) throw Error(r.status); return r.text(); }).then(t => { JSON.parse(t); require('fs').writeFileSync('/opt/retire-db/jsrepository-v5.json', t); }).catch(e => { console.error(e); process.exit(1); })"

FROM python:3.12-slim-bookworm AS wapiti-tools
RUN python -m venv --copies /opt/wapiti && /opt/wapiti/bin/pip install --no-cache-dir wapiti3==3.3.2

FROM python:3.12-slim-bookworm AS final-python-tools
RUN python -m venv --copies /opt/depscan && /opt/depscan/bin/pip install --no-cache-dir owasp-depscan==6.3.0
RUN python -m venv --copies /opt/nettacker && /opt/nettacker/bin/pip install --no-cache-dir nettacker==0.4.1
# Deliberately install only dependencies used by the remote REST/probe/detector profile;
# no local model backends or GPU frameworks are used in the HF integration.
RUN python -m venv --copies /opt/garak && /opt/garak/bin/pip install --no-cache-dir --no-deps garak==0.17.1 && /opt/garak/bin/pip install --no-cache-dir requests backoff jsonpath-ng PyYAML xdg-base-dirs colorama tqdm

FROM python:3.12-slim-bookworm AS idor-tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
# Pin the upstream core and retain its MIT license. No GUI or upstream CLI.
RUN mkdir -p /opt/idor-forge && curl -fsSL https://raw.githubusercontent.com/errorfiathck/IDOR-Forge/bc37cfc9143b40d7f91d1fa25753a22e908f4e84/core/IDORChecker.py -o /opt/idor-forge/IDORChecker.py && curl -fsSL https://raw.githubusercontent.com/errorfiathck/IDOR-Forge/bc37cfc9143b40d7f91d1fa25753a22e908f4e84/LICENSE -o /opt/idor-forge/LICENSE
RUN python -m venv --copies /opt/idor-forge-venv && /opt/idor-forge-venv/bin/pip install --no-cache-dir numpy==1.26.4 matplotlib==3.8.4 tabulate==0.9.0 requests==2.32.5 colorama==0.4.6 beautifulsoup4==4.14.3 pydantic==2.12.3

FROM zaproxy/zap-stable
USER root
COPY --from=wp-tools /usr/local/ /usr/local/
COPY --from=idor-tools /opt/idor-forge /opt/idor-forge
COPY --from=idor-tools /opt/idor-forge-venv /opt/idor-forge-venv
COPY --from=final-python-tools /opt/depscan /opt/depscan
COPY --from=final-python-tools /opt/nettacker /opt/nettacker
COPY --from=final-python-tools /opt/garak /opt/garak
COPY --from=pd-tools /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=pd-tools /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=pd-tools /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=pd-tools /usr/local/bin/kr /usr/local/bin/kr
COPY --from=pd-tools /usr/local/bin/amass /usr/local/bin/amass
COPY --from=js-tools /usr/local/bin/node /usr/local/bin/node
COPY --from=js-tools /usr/local/lib/node_modules/retire /opt/retire
COPY --from=js-tools /opt/retire-db /opt/retire-db
COPY --from=wapiti-tools /opt/wapiti /opt/wapiti
COPY --from=wapiti-tools /usr/local/bin/python3.12 /usr/local/bin/python3.12
COPY --from=wapiti-tools /usr/local/lib/libpython3.12.so* /usr/local/lib/
COPY --from=wapiti-tools /usr/local/lib/python3.12 /usr/local/lib/python3.12
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
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv python3-pip perl libxml-writer-perl libxml-libxml-perl libjson-perl libnet-ssleay-perl libio-socket-ssl-perl openssl libcurl4 libyaml-0-2 libgmp10 libffi8 libgdbm6 libgdbm-compat4 libreadline8 zlib1g procps dnsutils ldnsutils coreutils bsdextrautils xxd gawk socat curl libidn2-0 libstdc++6 libsqlite3-0 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/asfb-venv && /opt/asfb-venv/bin/pip install --no-cache-dir fastapi==0.115.12 uvicorn==0.34.2 python-multipart==0.0.20 httpx==0.28.1 arjun==2.2.7 PyYAML==6.0.2
WORKDIR /app
COPY --chown=zap:zap app /app/app
RUN test -s /app/app/nuclei-templates/technology-headers.yaml
COPY --chown=zap:zap start.sh /app/start.sh
RUN chmod +x /app/start.sh && mkdir -p /app/data/scanner-cache /home/zap/.cache/wpscan /home/zap/.config/garak /home/zap/.local/share/garak && cp -a /opt/wpscan-db /home/zap/.cache/wpscan/db && chown -R zap:zap /app/data /home/zap/.cache /home/zap/.config /home/zap/.local && ldconfig
USER zap
ENV GEM_HOME="/usr/local/bundle"
ENV PATH="/opt/asfb-venv/bin:/usr/local/bundle/bin:$PATH" PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["/app/start.sh"]
