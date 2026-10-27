#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"
if [ -d "/opt/dashboard-internal-soc-v3/venv" ]; then
    source /opt/dashboard-internal-soc-v3/venv/bin/activate
elif [ -d "/opt/dashboard-internal-soc/backend/venv" ]; then
    source /opt/dashboard-internal-soc/backend/venv/bin/activate
fi
PORT="${PORT:-8002}"
exec uvicorn pipeline.api:app --host 0.0.0.0 --port "$PORT"
