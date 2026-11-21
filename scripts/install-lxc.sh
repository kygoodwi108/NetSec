#!/usr/bin/env bash
# NetSec self-contained application install on a Debian 12/13 LXC (not the Proxmox host).
set -Eeuo pipefail
MODE=${1:-}
[[ "$MODE" == --fresh || "$MODE" == --upgrade ]] || { echo "Usage: bash scripts/install-lxc.sh --fresh|--upgrade" >&2; exit 2; }
[[ ${EUID} -eq 0 ]] || { echo 'Run as root INSIDE intended NetSec LXC.' >&2; exit 2; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ -r "$HERE/VERSION" && -r "$HERE/app/app.py" ]] || { echo 'Release directory incomplete' >&2; exit 2; }
[[ "$(cat "$HERE/VERSION")" == '1.2.0' ]] || { echo 'Release version mismatch' >&2; exit 2; }
APP=/opt/server-status
STATE=/var/lib/server-status
EXISTING=0
[[ -f "$APP/app.py" ]] && EXISTING=1
if [[ "$MODE" == --fresh && $EXISTING -eq 1 ]];then echo 'Existing NetSec installation: refusing overwrite. Use --upgrade only after backup/review.' >&2;exit 2;fi
if [[ "$MODE" == --upgrade && $EXISTING -eq 0 ]];then echo 'No existing NetSec installation. Use --fresh.' >&2;exit 2;fi
# For non-blank upgrades require known legacy NetSec markers; no blind overwrite.
if [[ "$MODE" == --upgrade ]] && ! grep -qE 'NetSec v3|NetSec product release v1.0.[12]|NetSec product release v1.1.[01]|NetSec product release v1.2.0|NetSec v1.2' "$APP/app.py"; then
 echo 'Unknown preexisting code: refusing upgrade' >&2; exit 2
fi
# Verify Python syntax and essential modules before touching live paths.
python3 - "$HERE" <<'PYCOMPILE'
import ast, pathlib, sys
root=pathlib.Path(sys.argv[1])/'app'
for f in root.glob('*.py'): ast.parse(f.read_text(), filename=str(f))
print('Python parse preflight PASS')
PYCOMPILE
BACKUP=
if [[ $EXISTING -eq 1 && ${NETSEC_PREBACKED_UP:-0} != 1 ]]; then
 BACKUP="/root/netsec-before-v120-$(date -u +%Y%m%dT%H%M%SZ)-$$"
 mkdir -m 0700 "$BACKUP"
 cp -a "$APP" "$BACKUP/server-status"
 for path in /etc/netsec-proxy-auth.json /etc/netsec-diagnostics.json /etc/netsec-ai.env; do
   [[ ! -e "$path" ]] || cp -a "$path" "$BACKUP/"
 done
 printf 'BACKUP DIRECTORY: %s\n' "$BACKUP"
fi
if ! getent passwd statusdash >/dev/null;then
 useradd --system --user-group --home-dir "$STATE" --shell /usr/sbin/nologin statusdash
fi
install -d -o root -g root -m 0755 "$APP"
install -d -o statusdash -g statusdash -m 0750 "$STATE"
for dir in ai intel;do install -d -o statusdash -g statusdash -m 0750 "$STATE/$dir";done
# Jimmy workspace SQLite and its WAL remain writable only by statusdash.
install -d -o statusdash -g statusdash -m 0750 "$STATE"
install -d -o root -g statusdash -m 0750 "$STATE/ban-queue"
for dir in requests results;do install -d -o statusdash -g statusdash -m 0700 "$STATE/ban-queue/$dir";done
for p in "$HERE"/app/*;do
 [[ -f "$p" ]] || continue
 install -o root -g root -m 0644 "$p" "$APP/$(basename "$p")"
done
if [[ ! -e "$APP/config.json" ]];then install -o root -g statusdash -m 0640 "$HERE/config/config.json.example" "$APP/config.json";fi
if [[ ! -e "$APP/operator-context.json" ]];then install -o root -g statusdash -m 0640 "$HERE/config/operator-context.json.example" "$APP/operator-context.json";fi
if [[ ! -e /etc/netsec-diagnostics.json ]];then install -o root -g statusdash -m 0640 "$HERE/config/netsec-diagnostics.json.example" /etc/netsec-diagnostics.json;fi
install -o root -g root -m 0755 "$HERE/scripts/netsec-ai-manual-runner" /usr/local/sbin/netsec-ai-manual-runner
install -o root -g root -m 0755 "$HERE/scripts/netsec-auto-update" /usr/local/sbin/netsec-auto-update
printf '1.2.0\n' > /etc/netsec-installed-version
chmod 0644 /etc/netsec-installed-version
for unit in "$HERE"/systemd/*;do install -o root -g root -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")";done
# Do NOT enable AI before /etc/netsec-ai.env exists; no automated changes to Nginx or CrowdSec.
systemctl daemon-reload
systemctl enable --now server-status.service
systemctl restart server-status.service
systemctl is-active --quiet server-status.service
# All v1.2 installations opt into unattended stable-release checks. Rollback is handled by the updater.
systemctl enable --now netsec-auto-update.timer
# Enable manual actions (including ban worker) but do not synthesize bans.
if [[ -x /usr/bin/cscli ]];then
 systemctl enable --now netsec-ban-worker.path netsec-alert-export.timer netsec-enforcement-export.timer
else echo 'CrowdSec not installed; manual bans and CrowdSec export units were not enabled.'
fi
if [[ -r /etc/netsec-ai.env ]] && ! grep -q 'REPLACE_WITH' /etc/netsec-ai.env; then
 systemctl enable --now netsec-ai.timer netsec-source-ai.timer netsec-ai-manual.path
else echo 'AI NOT enabled: configure /etc/netsec-ai.env then enable netsec-ai.timer, netsec-source-ai.timer and netsec-ai-manual.path.'
fi
printf '\nNetSec v1.2.0 installed. Application code: %s\n' "$APP"
printf 'Auth is fail-closed until /etc/netsec-proxy-auth.json and authenticated Nginx forwarding are configured.\n'
printf 'No host Nginx, CrowdSec decisions, browser credentials or private user data were overwritten.\n'
[[ -z "$BACKUP" ]] || printf 'Retain backup: %s\n' "$BACKUP"
