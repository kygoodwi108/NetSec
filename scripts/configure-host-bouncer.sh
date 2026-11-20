#!/usr/bin/env bash
# On Proxmox host after CrowdSec engine+relay and Nginx bouncer package are ready.
# ./configure-host-bouncer.sh <CTID> <LXC_IP>
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Must run as root on Proxmox host.' >&2; exit 1; }
[[ $# -eq 2 ]] || { echo "Usage: $0 <CTID> <CONTAINER_IP>" >&2; exit 2; }
CTID="$1"; CT_IP="$2"
python3 - "$CT_IP" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
if ip.version!=4 or not ip.is_private:raise SystemExit('Container IP must be private IPv4')
PY
command -v pct >/dev/null || { echo 'pct not found; run on Proxmox host.' >&2; exit 1; }
command -v nginx >/dev/null || { echo 'nginx not found; install it first.' >&2; exit 1; }
dpkg-query -W -f='${Status}' crowdsec-nginx-bouncer 2>/dev/null | grep -q 'install ok installed' || {
 echo 'crowdsec-nginx-bouncer not installed. See README.md for package installation.' >&2; exit 1; }
CONFIG=/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.local
KEYFILE=/root/netsec-nginx-bouncer.key
[[ -f /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf ]] || { echo 'Vendor bouncer configuration missing.' >&2; exit 1; }
if [[ -e "$CONFIG" || -e "$KEYFILE" ]]; then
  echo 'An existing local bouncer configuration or key exists; refusing to overwrite. Review manually.' >&2
  exit 1
fi
BOUNCER_NAME="netsec-nginx-pve-${CTID}"
KEY="$(pct exec "$CTID" -- cscli bouncers add "$BOUNCER_NAME" -o raw | tr -d '\r\n')"
if [[ ! "$KEY" =~ ^[A-Za-z0-9_./+=~-]{32,250}$ ]]; then
 echo 'CrowdSec registration returned an invalid key. No Nginx configuration changed. Check cscli bouncers list.' >&2
 exit 1
fi
umask 077
printf '%s\n' "$KEY" > "$KEYFILE"
chmod 600 "$KEYFILE"
# .local overrides main package configuration without replacing vendor settings.
cat > "$CONFIG" <<EOF
API_URL=http://${CT_IP}:8081
API_KEY=${KEY}
ENABLED=true
MODE=stream
UPDATE_FREQUENCY=10
BOUNCING_ON_TYPE=ban
CAPTCHA_PROVIDER=
EOF
unset KEY
chown root:www-data "$CONFIG" 2>/dev/null || chown root:root "$CONFIG"
chmod 640 "$CONFIG"
if ! nginx -t; then
  rm -f "$CONFIG"
  echo 'nginx -t failed. Removed new .conf.local; bouncer registration/key retained for recovery.' >&2
  exit 1
fi
systemctl reload nginx
if ! nginx -T 2>&1 | grep -Eqi 'crowdsec.*lua|lua.*crowdsec'; then
 echo 'WARNING: No CrowdSec Lua integration found in active nginx -T output. Verify package includes.' >&2
fi
echo 'Bouncer registered and host Nginx reloaded.'
echo "Secret key stored at ${KEYFILE} (root only); local config at ${CONFIG} (root / Nginx worker)."
echo 'NEXT: Run verified test ban/403, then delete the temporary test decision.'
