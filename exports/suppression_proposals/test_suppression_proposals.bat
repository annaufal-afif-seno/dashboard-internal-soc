@echo off
REM Automated Wazuh Logtest Verification Suite for Suppression Proposals
echo [*] Testing Wazuh XML Rule Suppression via wazuh-logtest...
echo [Sample Log] Nginx 404 UI Chunk Polling:
echo "2026/08/10 12:00:00 [error] 1234#1234: *1 connect() failed, client: 103.19.110.156, request: \"GET /dash/chunk/main.js HTTP/1.1\"" | /var/ossec/bin/wazuh-logtest 2>nul
echo [+] If Rule level is 0, suppression is verified!
