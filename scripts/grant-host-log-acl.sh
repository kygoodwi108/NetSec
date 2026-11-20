#!/usr/bin/env bash
# On Proxmox host, default UID mapping only; grant read to unprivileged statusdash in CT.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || exit 1
[[ $# -eq 1 ]] || { echo "Usage: $0 <CTID>" >&2; exit 2; }
CTID="$1"
pct config "$CTID" | grep -qx 'unprivileged: 1' || { echo 'CT is not marked unprivileged; refusing default UID mapping assumptions.' >&2; exit 1; }
if pct config "$CTID" | grep -q '^lxc.idmap:'; then echo 'Custom lxc.idmap detected; map statusdash UID manually.' >&2; exit 1; fi
[[ -d /var/log/nginx && -f /var/log/nginx/access.log ]] || { echo 'Nginx log folder absent on host.' >&2; exit 1; }
UID_CT="$(pct exec "$CTID" -- id -u statusdash)"
[[ "$UID_CT" =~ ^[0-9]+$ ]] || exit 1
UID_HOST="$((100000+UID_CT))"
ROOT_MAPPED_UID=100000
command -v setfacl >/dev/null || apt-get install -y acl
setfacl -m "u:${UID_HOST}:rx,u:${ROOT_MAPPED_UID}:rx" /var/log/nginx
find /var/log/nginx -maxdepth 1 -type f \( -name 'access.log*' -o -name 'error.log*' \) -exec setfacl -m "u:${UID_HOST}:r,u:${ROOT_MAPPED_UID}:r" {} +
setfacl -d -m "u:${UID_HOST}:rX,u:${ROOT_MAPPED_UID}:rX" /var/log/nginx
printf 'Granted mapped statusdash UID %s and mapped container root UID %s read-only access to Nginx logs.\n' "$UID_HOST" "$ROOT_MAPPED_UID"
pct exec "$CTID" -- runuser -u statusdash -- test -r /mnt/nginx-logs/access.log
pct exec "$CTID" -- test -r /mnt/nginx-logs/access.log
printf 'Verified: statusdash and CrowdSec container root can read access.log\n'
