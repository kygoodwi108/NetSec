#!/usr/bin/env bash
# Staging-safe standalone CrowdSec engine. Explicitly no Nginx host bouncer.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root inside a new NetSec LXC'; exit 2; }
[[ -r /mnt/nginx-logs/access.log ]] || { echo 'Read-only Nginx log mount/ACL absent'; exit 2; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates gnupg debian-archive-keyring
if ! grep -Rq 'packagecloud.io/crowdsec/crowdsec' /etc/apt/sources.list.d 2>/dev/null;then
  curl -fsSL --connect-timeout 8 --max-time 50 https://install.crowdsec.net -o /root/netsec-crowdsec-repository.sh
  bash /root/netsec-crowdsec-repository.sh
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec
cscli hub update
cscli collections install crowdsecurity/nginx || cscli collections upgrade crowdsecurity/nginx
mkdir -p /etc/crowdsec/acquis.d
cat > /etc/crowdsec/acquis.d/netsec-nginx.yaml <<'ACQUISITION'
filenames:
  - /mnt/nginx-logs/access.log
labels:
  type: nginx
ACQUISITION
systemctl enable --now crowdsec.service
systemctl restart crowdsec.service
systemctl enable --now netsec-alert-export.timer netsec-enforcement-export.timer
systemctl disable --now netsec-ban-worker.path || true
cscli lapi status
printf 'Independent detection engine ready. No production host bouncer modified.\n'
