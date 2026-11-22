#!/usr/bin/env bash
# Read-only host preflight for Canada-only inbound Nginx policy.
# No firewall modifications, no downloads, no reloads, no secrets.
set -Eeuo pipefail
echo "===== Canada-only policy: READ-ONLY host audit ====="
echo "UTC: $(date -u -Is)"
echo
echo "Nginx version / build:"
nginx -v 2>&1 || true
nginx -V 2>&1 | grep -oE '(http_v2|http_v3|geoip2|geoip_module)[^ ]*' | sort -u || true
echo
echo "GeoIP2 package:"
dpkg-query -W -f='${Package} ${Version} ${Status}\n' libnginx-mod-http-geoip2 2>/dev/null || true
echo "GeoIP2 module:"
ls /etc/nginx/modules-enabled/*geoip* 2>/dev/null || true
echo
echo "Nginx configuration syntax:"
nginx -t 2>&1 || true
echo
echo "Listeners (NOT proof of internet reachability):"
ss -lntup | awk 'NR==1 || /:(22|80|443|8006|3128|9091)[[:space:]]/' | head -40
echo
echo "Firewall state:"
if command -v pve-firewall >/dev/null;then pve-firewall status 2>&1 || true;fi
if command -v nft >/dev/null;then nft list tables 2>&1 || true;fi
echo
echo "WARNING: Country filtering at Nginx will NOT cover direct SSH, Proxmox or SPICE ports."
echo "WARNING: Router port forwards, IPv6, GeoIP2 database, real client IP chain,"
echo "         Certificate Authority renewal and console recovery must be verified."
echo "WARNING: Transmission worldwide exemption applies to torrent peers, NOT admin UI."
echo "No changes made."
