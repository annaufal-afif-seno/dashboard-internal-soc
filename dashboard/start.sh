#!/bin/bash
cd /opt/dashboard-internal-soc-v2/frontend
exec npm run dev -- --host 0.0.0.0 --port 5174
