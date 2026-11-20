#!/usr/bin/env bash
# Install CrowdSec engine in the NetSec LXC; Nginx runs on the Proxmox host.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root in the NetSec LXC.' >&2; exit 1; }
[[ -r /mnt/nginx-logs/access.log ]] || echo 'WARNING: /mnt/nginx-logs/access.log not yet readable; fix host bind mount ACLs.' >&2
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates gnupg debian-archive-keyring
if ! grep -Rq 'packagecloud.io/crowdsec/crowdsec' /etc/apt/sources.list.d/ 2>/dev/null; then
  echo 'Adding the official CrowdSec package repository (vendor repository script).'
  curl -fsSL --connect-timeout 8 --max-time 50 https://install.crowdsec.net -o /root/install-crowdsec-repo.sh
  bash /root/install-crowdsec-repo.sh
fi
apt-get update
apt-cache policy crowdsec | head -20
DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec
cscli hub update
cscli collections install crowdsecurity/nginx || cscli collections upgrade crowdsecurity/nginx
mkdir -p /etc/crowdsec/acquis.d
cat > /etc/crowdsec/acquis.d/netsec-nginx.yaml <<'EOF'
filenames:
  - /mnt/nginx-logs/access.log
labels:
  type: nginx
EOF
systemctl enable --now crowdsec
systemctl restart crowdsec
systemctl enable --now netsec-alert-export.timer netsec-enforcement-export.timer netsec-ban-worker.path
systemctl start netsec-alert-export.service netsec-enforcement-export.service || true
cat <<'EOF'
CrowdSec engine installed. Verify:
  cscli lapi status
  cscli metrics show acquisition
  cscli collections list | grep nginx
Next configure the restricted LAPI relay to the Nginx host (see README.md).
EOF
