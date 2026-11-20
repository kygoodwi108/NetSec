#!/usr/bin/env bash
# NetSec first-time Proxmox LXC installer (v1.0.2).
# Deliberately refuses overwrites. Does not configure a CrowdSec host bouncer.
set -Eeuo pipefail
umask 077
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

usage(){
  cat <<'HELP'
NetSec first-time Proxmox installer, v1.0.2
Usage: sudo bash scripts/proxmox-setup.sh

Interactive prompts: new LXC ID, static private IPv4/CIDR, gateway, DNS,
LXC storage/bridge, web hostname and login, AI name, provider (OpenAI API,
local Open WebUI, or none), model, and API key (hidden input).

Run on the Proxmox HOST from an extracted NetSec source checkout, NOT in an
existing NetSec container. It will never overwrite an existing LXC or Nginx
site; never replaces a host CrowdSec bouncer. Use --help to show this text.
HELP
}
[[ ${1:-} != --help ]] || { usage; exit 0; }
[[ $# -eq 0 ]] || { usage >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo 'Run as root on the Proxmox host.' >&2; exit 2; }
[[ -t 0 ]] || { echo 'Interactive terminal required. Do not pipe an API key into this script.' >&2; exit 2; }
for cmd in pct pveam pvesm python3 awk tar; do
  command -v "$cmd" >/dev/null || { echo "Missing required command: $cmd" >&2; exit 2; }
done
[[ $(cat "$HERE/VERSION") == 1.0.2 ]] || { echo 'Wrong source version' >&2; exit 2; }
[[ -f "$HERE/app/netsec_ai_provider.py" ]] || { echo 'Missing provider adapter' >&2; exit 2; }

ask(){
  local var="$1" label="$2" default="${3:-}" input
  if [[ -n "$default" ]];then
    read -r -p "$label [$default]: " input
    printf -v "$var" '%s' "${input:-$default}"
  else
    read -r -p "$label: " input
    printf -v "$var" '%s' "$input"
  fi
}
ask_secret(){ local var="$1" label="$2" value; read -r -s -p "$label: " value; printf '\n'; printf -v "$var" '%s' "$value"; }
yesno(){ local answer; read -r -p "$1 [${2:-y/N}]: " answer; [[ "$answer" =~ ^([Yy]|[Yy][Ee][Ss])$ ]]; }
die(){ echo "ERROR: $*" >&2; exit 2; }

printf '\nNetSec v1.0.2 — New installation wizard\n'
printf 'Existing NetSec LXCs and host bouncer configuration will not be modified.\n\n'
ask CTID 'New, unused LXC ID' '150'
[[ "$CTID" =~ ^[1-9][0-9]{1,5}$ ]] || die 'Invalid CTID'
[[ ! -e "/etc/pve/lxc/${CTID}.conf" ]] || die "LXC $CTID already exists"
ask HOSTNAME 'Container hostname' 'netsec'
[[ "$HOSTNAME" =~ ^[a-z][a-z0-9-]{0,40}$ ]] || die 'Hostname must be lowercase alphanumeric with hyphens'
ask CIDR 'Static private IP address/CIDR' '192.168.1.50/24'
ask GW 'LAN gateway IP' '192.168.1.1'
ask DNS 'DNS server IP (usually gateway)' "$GW"
ask BRIDGE 'Proxmox network bridge' 'vmbr0'
ask TEMPLATE_STORE 'Template storage' 'local'
ask ROOT_STORE 'LXC disk storage' 'local-lvm'
ask DISK_GB 'Container disk size (GiB)' '16'
[[ "$BRIDGE" =~ ^[a-zA-Z0-9_.-]+$ && "$TEMPLATE_STORE" =~ ^[a-zA-Z0-9_.-]+$ && "$ROOT_STORE" =~ ^[a-zA-Z0-9_.-]+$ ]] || die 'Invalid bridge or storage identifier'
[[ "$DISK_GB" =~ ^[0-9]{1,3}$ ]] && ((DISK_GB>=8 && DISK_GB<=512)) || die 'Disk size out of range (8-512 GiB)'
python3 - "$CIDR" "$GW" "$DNS" <<'PYVALIDATE' || die 'Static address, gateway, or DNS invalid'
import ipaddress,sys
iface=ipaddress.IPv4Interface(sys.argv[1]); gateway=ipaddress.IPv4Address(sys.argv[2]); dns=ipaddress.IPv4Address(sys.argv[3]); ip=iface.ip
rfc1918=any(ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
assert rfc1918 and iface.network.prefixlen<=30, 'Choose a private address on a LAN subnet'
assert gateway in iface.network and gateway!=ip and ip!=iface.network.network_address and ip!=iface.network.broadcast_address
assert dns.is_global or dns.is_private
PYVALIDATE
[[ -e "/sys/class/net/$BRIDGE" ]] || die "Network bridge $BRIDGE not found"
pvesm status | awk -v t="$TEMPLATE_STORE" '$1==t && $3=="active"{a=1}END{exit !a}' || die "Inactive template storage: $TEMPLATE_STORE"
pvesm status | awk -v t="$ROOT_STORE" '$1==t && $3=="active"{a=1}END{exit !a}' || die "Inactive root storage: $ROOT_STORE"
IP="${CIDR%/*}"
printf '\nImportant: reserve %s in your router/DHCP server. Ping does NOT prove an IP is unused.\n' "$IP"
if command -v ping >/dev/null && ping -c 1 -W 1 "$IP" >/dev/null 2>&1;then
  die "$IP responded to ping; choose an unused IP"
fi

ask AI_NAME 'Name your security AI assistant' 'Jimmy'
[[ "$AI_NAME" =~ ^[A-Za-z][A-Za-z0-9\ _-]{0,31}$ ]] || die 'Use 1-32 letters, digits, spaces, underscores or hyphens; start with a letter'
cat <<'CHOICE'
AI provider:
  1) OpenAI API — your own billable key; limited security telemetry leaves your network
  2) Open WebUI/Ollama — your existing local/private model and key
  3) None — monitoring dashboard only; AI can be configured later
CHOICE
ask PROVIDER_CHOICE 'Provider [1/2/3]' '3'
AI_PROVIDER='none'; AI_URL=''; AI_MODEL=''; AI_KEY=''
case "$PROVIDER_CHOICE" in
1)
  AI_PROVIDER='openai'
  AI_URL='https://api.openai.com'
  ask AI_MODEL 'OpenAI model supporting Chat Completions and JSON outputs' 'gpt-4.1-mini'
  echo 'An OpenAI API key is separate from ChatGPT subscriptions and incurs API usage charges.'
  ask_secret AI_KEY 'Enter YOUR OpenAI project API key (hidden)'
  ;;
2)
  AI_PROVIDER='openwebui'
  ask AI_URL 'Open WebUI URL (private HTTP IP or HTTPS)' 'http://192.168.1.20:3000'
  ask AI_MODEL 'Model identifier exposed by Open WebUI' 'qwen3:8b'
  ask_secret AI_KEY 'Enter YOUR Open WebUI API key (hidden)'
  ;;
3) ;;
*) die 'Choose 1, 2, or 3' ;;
esac
if [[ "$AI_PROVIDER" != none ]];then
  [[ "$AI_MODEL" =~ ^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}$ ]] || die 'Invalid model identifier'
  [[ "$AI_KEY" =~ ^[a-zA-Z0-9_.:/+=-]{8,500}$ ]] || die 'Invalid API key syntax (must not have spaces/newlines)'
  if [[ "$AI_PROVIDER" == openwebui ]];then
    python3 - "$AI_URL" <<'PYURL' || die 'Use https://hostname or a private LAN http://IP address for Open WebUI'
import sys,ipaddress
from urllib.parse import urlsplit
p=urlsplit(sys.argv[1]);assert p.scheme in ('http','https') and p.hostname and not p.username and not p.password and p.path in ('','/') and not p.query and not p.fragment
if p.scheme=='http':assert ipaddress.IPv4Address(p.hostname).is_private
PYURL
  else
    echo 'CLOUD PRIVACY: Requests may contain sampled security events, source IPs, and URLs.'
    yesno 'I agree to transmit this data to OpenAI using my key' || die 'OpenAI transfer not authorized'
  fi
fi

ask DOMAIN 'HTTPS dashboard hostname (leave blank to configure manually later)' ''
USE_PROXY=0
if [[ -n "$DOMAIN" ]];then
  [[ "$DOMAIN" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{2,190}$ && "$DOMAIN" == *.* && "$DOMAIN" != *..* ]] || die 'Invalid DNS hostname'
  command -v nginx >/dev/null || die 'Nginx is required on host for automated HTTPS setup; install it first'
  [[ ! -e "/etc/nginx/sites-available/$DOMAIN" && ! -e "/etc/nginx/sites-enabled/$DOMAIN" ]] || die 'That Nginx site already exists; refusing overwrite'
  ask EMAIL 'Email for Let’s Encrypt certificate notices' ''
  [[ "$EMAIL" == *@*.* && "$EMAIL" != *' '* ]] || die 'Enter a valid contact email'
  ask OP_USER 'Dashboard login username' 'netsecadmin'
  [[ "$OP_USER" =~ ^[A-Za-z][A-Za-z0-9_-]{0,31}$ ]] || die 'Invalid login username'
  ask_secret OP_PASS 'New dashboard password (hidden)'
  [[ ${#OP_PASS} -ge 12 && "$OP_PASS" != *$'\n'* ]] || die 'Use a password of at least 12 characters'
  command -v certbot >/dev/null || die 'certbot not installed on host; install it first'
  command -v htpasswd >/dev/null || die 'htpasswd not installed on host; install apache2-utils first'
  USE_PROXY=1
fi

USE_LOGS=0
if [[ -f /var/log/nginx/access.log ]] && yesno 'Read existing host Nginx logs (read-only mount and access ACLs)?';then USE_LOGS=1;fi
USE_CROWDSEC=0
if [[ $USE_LOGS == 1 ]] && yesno 'Install independent CrowdSec detection engine in new LXC (NO host bouncer)?';then USE_CROWDSEC=1;fi
ENABLE_AI=0
if [[ "$AI_PROVIDER" != none ]];then
  if [[ "$USE_LOGS" != 1 ]];then echo 'No Nginx log mount selected; AI assessments require readable Nginx logs.';fi
  echo 'AI timers run repeatedly and may use billable API tokens.'
  if [[ "$USE_LOGS" == 1 ]] && yesno 'Enable automatic AI assessment and classification timers?';then ENABLE_AI=1;fi
fi

printf '\nINSTALL PLAN (review carefully)\n'
printf 'LXC: %s (%s), static %s, gateway %s, DNS %s, bridge %s\n' "$CTID" "$HOSTNAME" "$CIDR" "$GW" "$DNS" "$BRIDGE"
printf 'Storage: %s/%s (%s GiB)\n' "$TEMPLATE_STORE" "$ROOT_STORE" "$DISK_GB"
printf 'Dashboard: %s; operator: %s; AI: %s / %s; assistant: %s\n' "${DOMAIN:-not configured}" "${OP_USER:-not configured}" "$AI_PROVIDER" "${AI_MODEL:-none}" "$AI_NAME"
printf 'Host log access: %s; CrowdSec detector: %s; scheduled AI: %s\n' "$USE_LOGS" "$USE_CROWDSEC" "$ENABLE_AI"
yesno 'Proceed and CREATE a new LXC and (if selected) Nginx site?' || { echo 'Cancelled: no changes made'; exit 0; }

STAGING="$(mktemp -d /run/netsec-setup.XXXXXXXX)"
cleanup(){ rm -rf -- "$STAGING"; unset AI_KEY OP_PASS || true; }
trap cleanup EXIT
trap 'echo "Installation interrupted. LXC $CTID may need manual cleanup; existing deployments were not overwritten." >&2' ERR

pveam update
TEMPLATE="$(pveam available --section system | awk '$2 ~ /^debian-12-standard_.*amd64\.tar\.zst$/ {print $2}' | sort -V | tail -1)"
[[ -n "$TEMPLATE" ]] || die 'Debian 12 template unavailable'
pveam list "$TEMPLATE_STORE" | grep -Fq "$TEMPLATE" || pveam download "$TEMPLATE_STORE" "$TEMPLATE"

pct create "$CTID" "$TEMPLATE_STORE:vztmpl/$TEMPLATE" \
  --hostname "$HOSTNAME" --ostype debian --unprivileged 1 \
  --cores 2 --memory 2048 --swap 512 --rootfs "$ROOT_STORE:$DISK_GB" \
  --net0 "name=eth0,bridge=$BRIDGE,ip=$CIDR,gw=$GW" \
  --nameserver "$DNS" --onboot 1
if [[ "$USE_LOGS" == 1 ]];then
  pct set "$CTID" -mp0 /var/log/nginx,mp=/mnt/nginx-logs,ro=1
fi
pct start "$CTID"
pct exec "$CTID" -- apt-get update
pct exec "$CTID" -- apt-get install -y python3 curl ca-certificates socat acl

# Distribute *exactly* the reviewed local sources; no blind network git checkout.
mkdir -p "$STAGING/source"
tar --exclude=.git --exclude='*.zip' -C "$HERE" -cf "$STAGING/netsec.tar" .
pct push "$CTID" "$STAGING/netsec.tar" /root/netsec-source.tar
pct exec "$CTID" -- mkdir -p /root/netsec-setup
pct exec "$CTID" -- tar -xf /root/netsec-source.tar -C /root/netsec-setup
pct exec "$CTID" -- bash -lc "cd /root/netsec-setup && bash ci/check.sh"
pct exec "$CTID" -- bash /root/netsec-setup/scripts/install-lxc.sh --fresh

# Prepare non-secret display name before enabling the AI workers.
pct exec "$CTID" -- python3 -c '
import json,sys,pathlib
p=pathlib.Path("/opt/server-status/config.json")
d=json.loads(p.read_text());d["assistant_name"]=sys.argv[1]
p.write_text(json.dumps(d,indent=2)+"\n")
' "$AI_NAME"
pct exec "$CTID" -- chown root:statusdash /opt/server-status/config.json
pct exec "$CTID" -- chmod 640 /opt/server-status/config.json

PROXY_IP="$(ip -4 route get "$IP" | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
[[ -n "$PROXY_IP" ]] || die 'Could not determine Proxmox Nginx source IP'
if [[ "$USE_PROXY" == 1 ]];then
  python3 - "$PROXY_IP" "$OP_USER" "$DOMAIN" "$STAGING/proxy.json" <<'PYJSON'
import json,sys
ip,user,domain,path=sys.argv[1:]
with open(path,'w') as f:
    json.dump({'trusted_proxy_ip':ip,'username':user,'origin':'https://'+domain},f)
    f.write('\n')
PYJSON
  pct push "$CTID" "$STAGING/proxy.json" /etc/netsec-proxy-auth.json
  pct exec "$CTID" -- chown root:statusdash /etc/netsec-proxy-auth.json
  pct exec "$CTID" -- chmod 640 /etc/netsec-proxy-auth.json
fi

if [[ "$AI_PROVIDER" != none ]];then
  {
    printf 'NETSEC_AI_PROVIDER=%s\n' "$AI_PROVIDER"
    printf 'NETSEC_AI_URL=%s\n' "$AI_URL"
    printf 'NETSEC_AI_MODEL=%s\n' "$AI_MODEL"
    printf 'NETSEC_AI_KEY=%s\n' "$AI_KEY"
    printf 'NETSEC_ASSISTANT_NAME="%s"\n' "$AI_NAME"
    printf 'NETSEC_PUBLIC_URL=https://%s/\n' "${DOMAIN:-localhost}"
    printf 'NETSEC_SOURCE_AI_BATCHES=4\nNETSEC_SOURCE_AI_BATCH_SIZE=10\n'
  } > "$STAGING/ai.env"
  chmod 600 "$STAGING/ai.env"
  pct push "$CTID" "$STAGING/ai.env" /etc/netsec-ai.env
  pct exec "$CTID" -- chown root:statusdash /etc/netsec-ai.env
  pct exec "$CTID" -- chmod 640 /etc/netsec-ai.env
  # Do not retain API secrets unnecessarily in the shell after secure transfer.
  AI_KEY=''
fi

if [[ "$USE_LOGS" == 1 ]];then
  bash "$HERE/scripts/grant-host-log-acl.sh" "$CTID"
fi
if [[ "$USE_CROWDSEC" == 1 ]];then
  pct exec "$CTID" -- bash /root/netsec-setup/scripts/install-crowdsec-detector.sh
fi

if [[ "$USE_PROXY" == 1 ]];then
  mkdir -p /var/www/letsencrypt/.well-known/acme-challenge
  AUTHFILE="/etc/nginx/.htpasswd-netsec-${DOMAIN}"
  [[ ! -e "$AUTHFILE" ]] || die 'Password file already exists; refusing overwrite'
  printf '%s\n' "$OP_PASS" | htpasswd -i -B -c "$AUTHFILE" "$OP_USER" >/dev/null
  OP_PASS=''
  chmod 640 "$AUTHFILE"
  # Nginx workers must be able to read this file; use its existing configured group.
  if getent group www-data >/dev/null;then chgrp www-data "$AUTHFILE";fi
  SITE="/etc/nginx/sites-available/$DOMAIN"
  cat > "$SITE" <<HTTPONLY
server {
    listen 80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root /var/www/letsencrypt; try_files \$uri =404; }
    location / { return 301 https://\$host\$request_uri; }
}
HTTPONLY
  ln -s "$SITE" "/etc/nginx/sites-enabled/$DOMAIN"
  nginx -t && systemctl reload nginx
  CERTDIR="/etc/letsencrypt/live/$DOMAIN"
  if [[ ! -s "$CERTDIR/fullchain.pem" || ! -s "$CERTDIR/privkey.pem" ]];then
    echo "Ensure $DOMAIN resolves to this host, inbound TCP/80 is reachable, and Cloudflare does not block HTTP-01."
    certbot certonly --non-interactive --agree-tos --webroot -w /var/www/letsencrypt -m "$EMAIL" -d "$DOMAIN"
  fi
  cat > "$SITE" <<HTTPS
server {
    listen 80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root /var/www/letsencrypt; try_files \$uri =404; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name $DOMAIN;
    ssl_certificate $CERTDIR/fullchain.pem;
    ssl_certificate_key $CERTDIR/privkey.pem;
    location / {
        auth_basic "NetSec Security Dashboard";
        auth_basic_user_file $AUTHFILE;
        proxy_pass http://$IP:8787;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-NetSec-Authenticated-User \$remote_user;
        proxy_set_header Authorization "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
}
HTTPS
  nginx -t && systemctl reload nginx
fi

pct exec "$CTID" -- systemctl restart server-status.service
pct exec "$CTID" -- systemctl is-active --quiet server-status.service
pct exec "$CTID" -- curl -fsS http://127.0.0.1:8787/api/status >/dev/null
if [[ "$ENABLE_AI" == 1 && "$USE_LOGS" == 1 ]];then
  pct exec "$CTID" -- systemctl enable --now netsec-ai.timer netsec-source-ai.timer netsec-ai-manual.path
fi
# CrowdSec is observation-only by default. Never connect it to a production bouncer.
pct exec "$CTID" -- systemctl disable --now netsec-ban-worker.path >/dev/null 2>&1 || true
printf '\nINSTALL COMPLETE: NetSec on LXC %s at %s\n' "$CTID" "$IP"
if [[ "$USE_PROXY" == 1 ]];then
  printf 'HTTPS dashboard: https://%s\n' "$DOMAIN"
  printf 'Login user: %s (password not printed)\n' "$OP_USER"
else
  echo 'No HTTPS site configured; privileged UI actions remain disabled until authenticated Nginx is configured.'
fi
printf 'AI: %s | assistant: %s | timers enabled: %s\n' "$AI_PROVIDER" "$AI_NAME" "$ENABLE_AI"
echo 'To finish: review docs/INSTALL_FROM_SCRATCH.md; configure CrowdSec bouncer only after separate review.'
