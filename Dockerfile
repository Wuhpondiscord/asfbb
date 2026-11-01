FROM debian:bookworm-slim AS pd-tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/n.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip && unzip -oq /tmp/n.zip nuclei -d /usr/local/bin
RUN curl -fsSL -o /tmp/k.zip https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana_1.8.0_linux_amd64.zip && unzip -oq /tmp/k.zip katana -d /usr/local/bin
FROM zaproxy/zap-stable
USER root
COPY --from=pd-tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=pd-tools /usr/local/bin/katana /usr/local/bin/katana
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv python3-pip && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/asfb-venv && /opt/asfb-venv/bin/pip install --no-cache-dir fastapi==0.115.12 uvicorn==0.34.2 python-multipart==0.0.20 httpx==0.28.1
WORKDIR /app
COPY --chown=zap:zap app /app/app
COPY --chown=zap:zap start.sh /app/start.sh
RUN chmod +x /app/start.sh && mkdir -p /app/data && chown zap:zap /app/data
USER zap
ENV PATH="/opt/asfb-venv/bin:$PATH" PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["/app/start.sh"]
