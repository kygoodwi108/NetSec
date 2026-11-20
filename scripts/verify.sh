#!/usr/bin/env bash
set -u
echo '=== NetSec services ==='
systemctl --no-pager --plain is-active server-status.service crowdsec.service netsec-ai.timer netsec-source-ai.timer netsec-ban-worker.path netsec-ai-manual.path netsec-push.timer netsec-geoip-update.timer netsec-alert-export.timer netsec-enforcement-export.timer || true
echo '=== Timer status ==='
systemctl --no-pager list-timers --all | grep -E 'netsec' || true
echo '=== Dashboard localhost API ==='
curl --max-time 15 -sS -o /dev/null -w 'GET /api/status -> %{http_code}\n' http://127.0.0.1:8787/api/status || true
echo '=== Operator auth policy ==='
if [[ -e /etc/netsec-proxy-auth.json ]]; then echo 'Proxy pin file present; confirm correct source IP / user / HTTPS origin';else echo 'Not configured: privileged routes fail closed';fi
echo '=== Python ==='
/usr/bin/python3 -m compileall -q /opt/server-status && echo 'Syntax OK'

echo '=== Jimmy PWA/Workspace ==='
for path in /manifest.webmanifest /sw.js /offline.html /icon-192.png;do
  curl --max-time 10 -sS -o /dev/null -w "GET $path -> %{http_code}\n" "http://127.0.0.1:8787$path" || true
done
echo '=== Persistent Jimmy workspace ==='
if [[ -e /var/lib/server-status/jimmy-workspace.sqlite3 ]];then
  ls -l /var/lib/server-status/jimmy-workspace.sqlite3
else echo 'No conversations/feedback yet (expected on first install)';fi
