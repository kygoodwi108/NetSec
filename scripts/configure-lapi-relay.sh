#!/usr/bin/env bash
# Inside LXC: ./configure-lapi-relay.sh CT_LAN_IP PVE_HOST_LAN_IP
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || exit 1
[[ $# -eq 2 ]] || { echo "Usage: $0 <CONTAINER_IP> <PROXMOX_HOST_IP>" >&2; exit 2; }
python3 - "$1" "$2" <<'PY'
import ipaddress,sys
for item in sys.argv[1:]:
    address=ipaddress.ip_address(item)
    if address.version!=4 or not address.is_private: raise SystemExit('Use private LAN IPv4 addresses only')
PY
command -v socat >/dev/null
[[ -f /etc/crowdsec/local_api_credentials.yaml ]] || { echo 'CrowdSec LAPI credentials missing; install CrowdSec first.' >&2; exit 1; }
cat > /etc/systemd/system/netsec-lapi-relay.service <<EOF
[Unit]
Description=CrowdSec LAPI relay restricted to Proxmox reverse proxy host
After=network-online.target crowdsec.service
Requires=crowdsec.service

[Service]
Type=simple
User=nobody
ExecStart=/usr/bin/socat TCP4-LISTEN:8081,bind=$1,reuseaddr,fork,range=$2/32 TCP4:127.0.0.1:8080
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now netsec-lapi-relay.service
systemctl --no-pager status netsec-lapi-relay.service | head -15
printf 'LAPI relay: %s:8081, accepting only %s/32. No router port forward needed.\n' "$1" "$2"
