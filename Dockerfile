FROM zaproxy/zap-stable
USER root
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
