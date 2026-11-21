#!/usr/bin/env bash
# Fresh PatchMon companion install. Run INSIDE a dedicated Debian VM, never in NetSec/PVE.
set -Eeuo pipefail
umask 077
if [[ ${EUID} -ne 0 ]];then echo 'Run as root inside a dedicated Debian VM.' >&2;exit 2;fi
if [[ ! -f /etc/os-release ]];then echo 'Cannot identify distribution.' >&2;exit 2;fi
. /etc/os-release
if [[ ${ID:-} != debian || ! ${VERSION_ID:-} =~ ^(12|13)$ ]];then
  echo 'This helper supports Debian 12/13 dedicated VMs only.' >&2;exit 2
fi
if [[ -e /opt/server-status/app.py || -e /etc/pve/.members || -e /etc/netsec-installed-version ]];then
  echo 'Refusing to run on NetSec or Proxmox. Use a separate Debian VM.' >&2;exit 2
fi
printf '%s\n' 'PatchMon runs a Docker stack with persistent database and credentials.'
printf '%s\n' 'Review the upstream setup script before running it. Ensure this is a fresh dedicated VM.'
read -r -p 'Enter INSTALL to download and inspect the upstream installer: ' answer
[[ $answer == INSTALL ]] || { echo 'Cancelled';exit 1; }
apt-get update
apt-get install -y ca-certificates curl
url=https://raw.githubusercontent.com/PatchMon/PatchMon/refs/heads/main/setup-docker.sh
curl -fLSs --proto '=https' --tlsv1.2 --max-time 45 "$url" -o /root/patchmon-upstream-setup.sh
chmod 0600 /root/patchmon-upstream-setup.sh
echo '=== Review /root/patchmon-upstream-setup.sh, then run it ==='
echo 'less /root/patchmon-upstream-setup.sh'
echo 'bash /root/patchmon-upstream-setup.sh'
echo 'Instructions for NetSec integration: docs/PATCHMON.md in your NetSec repo.'
