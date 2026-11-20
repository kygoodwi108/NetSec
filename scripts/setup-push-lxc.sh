#!/usr/bin/env bash
# Optional step inside a fresh NetSec LXC with an authenticated HTTPS origin.
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'Run as root in NetSec LXC'; exit 2; }
[[ $# == 2 ]] || { echo 'Usage: setup-push-lxc.sh <https-origin> <email>'; exit 2; }
ORIGIN="$1" EMAIL="$2"
python3 - "$ORIGIN" "$EMAIL" <<'PY'
import sys
from urllib.parse import urlsplit
p=urlsplit(sys.argv[1]);assert p.scheme=='https' and p.hostname and not p.username and not p.password and p.path in ('','/') and not p.query and not p.fragment
assert '@' in sys.argv[2] and not any(x in sys.argv[2] for x in ('\n','\r',' '))
PY
[[ ! -e /etc/netsec-push.json && ! -e /etc/netsec-push-private.pem ]] || { echo 'Existing push identity detected; refusing to rotate in place.' >&2; exit 2; }
apt-get -o Acquire::Retries=3 update
DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 install -y python3-venv
python3 -m venv /opt/netsec-push-venv
/opt/netsec-push-venv/bin/python -m pip install --disable-pip-version-check 'pywebpush==2.5.0'
# Real device subscriptions use this server's VAPID identity. Keep the key
# private; rotation requires resubscribing devices, not silent migration.
/opt/netsec-push-venv/bin/python - "$ORIGIN" "$EMAIL" <<'PY'
import base64,json,sys,os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
private=ec.generate_private_key(ec.SECP256R1())
pem=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
public=private.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
key=base64.urlsafe_b64encode(public).decode().rstrip('=')
with open('/etc/netsec-push-private.pem','xb') as f:f.write(pem)
with open('/etc/netsec-push.json','x') as f:
 json.dump({'origin':sys.argv[1].rstrip('/'),'subject':'mailto:'+sys.argv[2],
            'private_key_path':'/etc/netsec-push-private.pem','public_key':key},f)
 f.write('\n')
PY
chown root:statusdash /etc/netsec-push.json /etc/netsec-push-private.pem
chmod 640 /etc/netsec-push.json /etc/netsec-push-private.pem
systemctl daemon-reload
systemctl enable --now netsec-push.timer
systemctl start netsec-push.service || true
printf 'Web Push ready. HTTPS users must sign in and opt in on each device.\n'
