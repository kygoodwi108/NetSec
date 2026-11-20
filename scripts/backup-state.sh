#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root INSIDE NetSec LXC' >&2;exit 2; }
DEST=${1:?Usage: bash scripts/backup-state.sh /root/your-private-backup.tar.gz}
[[ "$DEST" == /* ]] || { echo 'Destination must be absolute' >&2;exit 2; }
[[ ! -e "$DEST" ]] || { echo 'Destination already exists; refusing overwrite' >&2;exit 2; }
umask 077
# Bundle private state/config for RESTORE ONLY. Never commit this tarball.
tar -czpf "$DEST" --ignore-failed-read \
  /var/lib/server-status /opt/server-status/config.json \
  /opt/server-status/operator-context.json \
  /etc/netsec-proxy-auth.json /etc/netsec-diagnostics.json /etc/netsec-ai.env
chmod 600 "$DEST"
echo "PRIVATE BACKUP CREATED: $DEST"
