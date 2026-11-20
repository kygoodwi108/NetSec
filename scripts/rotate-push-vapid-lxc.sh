#!/usr/bin/env bash
# Manual key rotation invalidates all browser subscriptions by design.
# Never embed VAPID identity or browser keys in a public source ZIP.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 && $# == 1 && "$1" == ROTATE-VAPID ]] || {
  echo 'Usage: root inside NetSec LXC: bash scripts/rotate-push-vapid-lxc.sh ROTATE-VAPID' >&2;exit 2;
}
[[ -s /etc/netsec-push.json && -s /etc/netsec-push-private.pem ]] || { echo 'No current VAPID identity'; exit 2; }
[[ -x /opt/netsec-push-venv/bin/python ]] || { echo 'Push venv absent'; exit 2; }
BACKUP="/root/netsec-push-key-backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 0700 "$BACKUP"
cp -a /etc/netsec-push.json /etc/netsec-push-private.pem "$BACKUP/"
systemctl stop netsec-push.timer || true
/opt/netsec-push-venv/bin/python <<'PY'
import base64,json,os,pathlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
old=pathlib.Path('/etc/netsec-push.json');cfg=json.loads(old.read_text())
private=ec.generate_private_key(ec.SECP256R1())
pem=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
public=private.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
key=base64.urlsafe_b64encode(public).decode().rstrip('=')
cfg['public_key']=key
with open('/etc/.netsec-push-private-next.pem','xb') as f:f.write(pem)
with open('/etc/.netsec-push-next.json','x') as f:json.dump(cfg,f);f.write('\n')
os.chmod('/etc/.netsec-push-private-next.pem',0o640)
os.chmod('/etc/.netsec-push-next.json',0o640)
PY
chown root:statusdash /etc/.netsec-push-private-next.pem /etc/.netsec-push-next.json
mv /etc/.netsec-push-private-next.pem /etc/netsec-push-private.pem
mv /etc/.netsec-push-next.json /etc/netsec-push.json
# Existing browsers must opt in again using the new applicationServerKey.
runuser -u statusdash -- python3 - <<'PY'
import sys
sys.path.insert(0,'/opt/server-status')
import netsec_jimmy_store as s
with s.db() as c:c.execute('DELETE FROM subscriptions')
PY
systemctl start netsec-push.timer
printf 'VAPID key rotated. Previous keys privately archived: %s\n' "$BACKUP"
printf 'All subscriptions invalidated; users must enable notifications again on each device.\n'
