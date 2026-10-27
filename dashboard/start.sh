#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"
PORT="${VITE_PORT:-5175}"
exec npm run dev -- --host 0.0.0.0 --port "$PORT"
