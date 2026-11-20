#!/usr/bin/env bash
# Configure the host-wide CrowdSec Nginx bouncer to use a NEW NetSec CrowdSec LAPI.
# Usage: bash configure-host-bouncer.sh <CTID> <LXC_IPV4> --new|--cutover
# Must not be used on an active installation unless the operator authorized
# the associated cutover in the host installer. Backups are retained on host.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Root on Nginx host required.' >&2; exit 2; }
[[ $# -eq 3 && "$3" =~ ^(--new|--cutover)$ ]] || { echo 'Usage: <CTID> <LXC_IP> --new|--cutover' >&2; exit 2; }
CTID="$1"; CT_IP="$2"; MODE="$3"
[[ "$CTID" =~ ^[1-9][0-9]{1,5}$ ]] || exit 2
python3 - "$CT_IP" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1]); assert ip.version == 4 and ip.is_private
PY
for exe in pct nginx python3;do command -v "$exe" >/dev/null || exit 2;done
pkg_status=$(dpkg-query -W -f='${Status}' crowdsec-nginx-bouncer 2>/dev/null || true)
[[ "$pkg_status" == 'install ok installed' ]] || { echo 'crowdsec-nginx-bouncer package missing.' >&2; exit 2; }
CONFIG=/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf
OVERRIDE=/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.local
[[ -f "$CONFIG" ]] || { echo "Vendor config $CONFIG is missing." >&2; exit 2; }
if [[ -e "$OVERRIDE" ]];then
  echo "Found $OVERRIDE. Version-dependent override precedence; refuse automatic change. Reconcile manually." >&2
  exit 2
fi
if [[ "$MODE" == --new ]];then
  # Do not seize an existing, working Nginx bouncer from another LAPI.
  if grep -Eq '^\s*API_KEY\s*=\s*[^#[:space:]]{12,}' "$CONFIG";then
    echo 'Existing Nginx bouncer API key detected. Choose explicit cutover, not new installation.' >&2
    exit 2
  fi
fi
# Ensure remote relay is accessible before touching a working host bouncer.
python3 - "$CT_IP" <<'PY'
import socket,sys
with socket.create_connection((sys.argv[1],8081),timeout=5):pass
PY
BACKUP="/root/netsec-bouncer-backups/$(date -u +%Y%m%dT%H%M%SZ)-ct${CTID}"
mkdir -m 0700 -p "$BACKUP"
cp -a "$CONFIG" "$BACKUP/crowdsec-nginx-bouncer.conf"
nginx -t >/dev/null
NAME="netsec-nginx-ct${CTID}-$(date -u +%Y%m%d%H%M%S)"
KEY="$(pct exec "$CTID" -- cscli bouncers add "$NAME" -o raw | tr -d '\r\n')"
if [[ ! "$KEY" =~ ^[A-Za-z0-9_./+=~-]{32,250}$ ]];then
  echo 'CrowdSec bouncer registration returned invalid credentials; Nginx untouched.' >&2
  exit 1
fi
# Credential only ever passes through stdin; avoid exposing it on the process command line.
export NETSEC_BOUNCER_LAPI="http://${CT_IP}:8081"
if ! python3 - "$CONFIG" 3<<<"$KEY" <<'PYWRITE'
import os,pathlib,re,sys
config=pathlib.Path(sys.argv[1]); key=os.fdopen(3).read().strip()
if not key:raise SystemExit('Missing key')
content=config.read_text()
for field,value in [('API_URL',os.environ['NETSEC_BOUNCER_LAPI']),('API_KEY',key),('ENABLED','true'),('MODE','stream')]:
    pat=re.compile(r'^'+field+r'\s*=.*$',re.M)
    if pat.search(content):content=pat.sub(lambda m, v=value, f=field:f+'='+v,content,count=1)
    else:content+='\n'+field+'='+value+'\n'
config.write_text(content)
PYWRITE
then
  cp -a "$BACKUP/crowdsec-nginx-bouncer.conf" "$CONFIG"
  echo 'Writing bouncer config failed; restored backup.' >&2
  exit 1
fi
unset KEY NETSEC_BOUNCER_LAPI
chown root:www-data "$CONFIG" 2>/dev/null || chown root:root "$CONFIG"
chmod 0640 "$CONFIG"
if ! nginx -t;then
  cp -a "$BACKUP/crowdsec-nginx-bouncer.conf" "$CONFIG"
  nginx -t || true
  echo 'Nginx validation failed; restored old bouncer config.' >&2
  exit 1
fi
if ! systemctl reload nginx;then
  cp -a "$BACKUP/crowdsec-nginx-bouncer.conf" "$CONFIG"
  nginx -t && systemctl reload nginx || true
  echo 'Nginx reload failed; restored previous bouncer config.' >&2
  exit 1
fi
printf 'Host Nginx bouncer config updated. Backup: %s\n' "$BACKUP"
echo 'Registered, NOT YET PROVEN ENFORCING: verify cscli bouncers list last pull and controlled ban before enabling operator manual bans.'
