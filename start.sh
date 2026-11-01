#!/bin/sh
set -eu
: "${ASFB_API_KEY:?Set ASFB_API_KEY in Space secrets}"
: "${ZAP_API_KEY:?Set ZAP_API_KEY in Space secrets}"
/zap/zap.sh -daemon -host 127.0.0.1 -port 8090 -config "api.key=${ZAP_API_KEY}" -config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false > /tmp/asfb-zap.log 2>&1 &
exec uvicorn app.main:app --host 0.0.0.0 --port 7860
