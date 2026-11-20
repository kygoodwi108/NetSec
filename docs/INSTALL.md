# Fresh installation — NetSec v1.0.2

For automated new Proxmox deployments including a static IP and user-owned AI key, see **`docs/INSTALL_FROM_SCRATCH.md`**. This manual guide remains available for users who already built an LXC.

**Targets:** Debian 12/13 unprivileged LXC on Proxmox VE; Nginx reverse proxy on host. Python stdlib app; no Docker. Does **not** automatically install/alter the production host's Nginx/bouncer. Use a **new container** for a fresh install, not an existing working LXC. You need a working Linux/Proxmox admin account.

## 0. Before any changes
- Create a Proxmox backup/snapshot. Keep the host's existing Nginx sites and SSL certificates intact.
- Confirm a free LXC ID, IP, DNS name, firewall and backup location. Do not publish LAPI 8080/8081 or dashboard 8787 directly to the internet.
- The package **does not include** your passwords, API keys, historical logs, IP labels or CrowdSec decisions. Production restoration requires the private state backup described in `MIGRATION.md`.

## 1. Example new LXC (on Proxmox host)
Adapt every placeholder below; do **not** paste unchanged:

```bash
CTID=150
CT_IP=192.168.1.50
GW_IP=192.168.1.1
TEMPLATE_STORAGE=local
ROOT_STORAGE=local-lvm
pveam update
pveam available --section system | grep debian-12-standard
# Select a real template volume from your own pveam list, download it and set TEMPLATE.
# pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
pct create "$CTID" "$TEMPLATE_STORAGE:vztmpl/$TEMPLATE" --hostname netsec \
  --ostype debian --unprivileged 1 --cores 2 --memory 2048 --swap 512 \
  --rootfs "$ROOT_STORAGE:12" \
  --net0 "name=eth0,bridge=vmbr0,ip=$CT_IP/24,gw=$GW_IP" --onboot 1
# After confirming host Nginx is really logging in /var/log/nginx:
pct set "$CTID" -mp0 /var/log/nginx,mp=/mnt/nginx-logs,ro=1
pct start "$CTID"
pct exec "$CTID" -- apt-get update
pct exec "$CTID" -- apt-get install -y python3 curl ca-certificates socat acl
```

Template and storage IDs vary. The app itself will work without CrowdSec, but CrowdSec dashboards won't report full enforcement until the detection/bouncer steps are installed. Existing CrowdSec installations must be reconciled manually to avoid duplicates.

## 2. Transfer the ZIP (workstation -> Proxmox -> LXC)
Download `netsec-v1.0.2-source.zip` on your Mac and upload to host via SSH (if you have SSH access):

```bash
scp ~/Downloads/netsec-v1.0.2-source.zip root@YOUR_PVE_IP:/root/
```

**When remote without SSH:** upload from Mac to the same temporary HTTPS transfer service you normally use and copy the link; in the Proxmox web Shell run `curl -fL -o /root/netsec-v1.0.2-source.zip 'YOUR_TEMPORARY_URL'`. Temporary uploads can expose code to the provider, so don't include runtime secrets in the ZIP. Verify the release checksum printed alongside your download before installing.

On Proxmox host:

```bash
sha256sum /root/netsec-v1.0.2-source.zip
pct push "$CTID" /root/netsec-v1.0.2-source.zip /root/netsec-v1.0.2-source.zip
pct exec "$CTID" -- python3 -m zipfile -e /root/netsec-v1.0.2-source.zip /root
pct exec "$CTID" -- bash /root/netsec-v1.0.2/scripts/install-lxc.sh --fresh
```

The installer checks source syntax, installs complete app modules, creates the non-root `statusdash` account and private state paths, installs the provided systemd definitions, then starts `server-status.service`. It **does not** create or change a host Nginx vhost or CrowdSec decision; it preserves existing configs and disables optional AI timers until configured.

## 3. Configure app and verified login (inside the LXC)
Edit `/opt/server-status/config.json`, particularly log glob paths and `services`; ensure private config remains root:statusdash 0640. Keep the dashboard listener on the private LXC network only. `ALLOW_REMOTE_BIND=YES` is set by the controlled systemd unit.

```bash
cp /root/netsec-v1.0.2/config/netsec-proxy-auth.json.example /etc/netsec-proxy-auth.json
nano /etc/netsec-proxy-auth.json
chown root:statusdash /etc/netsec-proxy-auth.json
chmod 640 /etc/netsec-proxy-auth.json
```

Set `trusted_proxy_ip` to the **address of the Nginx host as actually seen by the LXC**, `username` to the HTTP Basic Auth account to authorize operator writes (default: `netsecadmin`), and `origin` to the exact `https://YOUR_NETSEC_HOSTNAME` URL (no path/port). If the proxy source IP changes, operator actions intentionally fail closed. Do not place sample values into production.

On Proxmox host: provision HTTPS + an Nginx Basic Auth password file; copy the *location block* in `examples/nginx-location.conf` into the appropriate existing NetSec HTTPS server block and replace its upstream IP. The crucial directives are:

```nginx
auth_basic "NetSec Security Dashboard";
auth_basic_user_file /etc/nginx/.htpasswd-netsec;
proxy_set_header X-NetSec-Authenticated-User $remote_user;
proxy_set_header Authorization "";
```

**Important:** authenticated proxy identity must never be trusted from an untrusted direct connection. Block direct network access to port 8787 except from the reverse proxy, and verify direct-to-LXC `/api/operator/session` returns 403. Do not grant public access to upstream port 8787.

Run `nginx -t && systemctl reload nginx` **only after** a successful syntax check. A browser login popup from Nginx is normal on initial login; token-bearing API requests must not override Basic Auth.

## 4. CrowdSec and Nginx log access
- On the host, make `/var/log/nginx` readable through read-only `mp0`. For an unprivileged LXC, map UID/GID correctly and grant **read** ACL to log files, not world-readable permissions. The helper `scripts/grant-host-log-acl.sh` is available but review its assumptions about default UID mappings and source layout first.
- The standalone package contains `scripts/install-crowdsec-lxc.sh` for a new engine. It uses the official CrowdSec repo and `crowdsecurity/nginx` collection. Installing Nginx bouncer is a **separate host change**, not performed by the core installer.
- `scripts/configure-lapi-relay.sh` and `scripts/configure-host-bouncer.sh` are included as reviewed examples for a new deployment. They rely on the host's actual CrowdSec/LAPI/Nginx versions; do not use atop an existing bouncer without reconciliation. Require testing of decision enforcement and LAPI last pull.
- Read-only alert/enforcement export timers are enabled only if `/usr/bin/cscli` is already present at install time. Enable them manually after installing CrowdSec if it was absent: `systemctl enable --now netsec-ban-worker.path netsec-alert-export.timer netsec-enforcement-export.timer`.

## 5. Jimmy/Open WebUI
Inside the LXC:

```bash
cp /root/netsec-v1.0.2/config/netsec-ai.env.example /etc/netsec-ai.env
nano /etc/netsec-ai.env
chown root:statusdash /etc/netsec-ai.env
chmod 640 /etc/netsec-ai.env
systemctl enable --now netsec-ai.timer netsec-source-ai.timer netsec-ai-manual.path
systemctl start netsec-ai.service
journalctl -u netsec-ai.service -n 35 --no-pager
```

Use a *dedicated* local model API key and real Open WebUI model. No remote model deployment is bundled. The worker sends bounded relevant log-derived facts to that configured endpoint; do not route confidential logs to an untrusted third party.

Optional offline country lookup (after installing the service and ensuring Internet access): `runuser -u statusdash -- python3 /opt/server-status/geoip_update.py`. The SQLite output is written into `/var/lib/server-status/geoip-country.sqlite3`, matching the sample app config.

## 6. Sensitive-path probing
By default `sensitive_probe_mode=rotating`, `sensitive_probe_source_allowlisted=false` and the worker is rate-limited. Only set `full` and `true` **after** identifying the actual source address recorded by the reverse proxy and applying a narrow CrowdSec allowlist; an allowlist exempts other traffic from that IP, too. Do not accept a JSON `true` as proof of CrowdSec allowance. The worker only tests approved HTTPS hosts at the configured private proxy IP and uses bounded read-only GETs.

## 7. Verification (inside LXC / from host)

```bash
bash /root/netsec-v1.0.2/scripts/verify.sh
systemctl list-timers --all | grep netsec
journalctl -u server-status.service -n 30 --no-pager
curl -sS http://127.0.0.1:8787/api/status | python3 -m json.tool | head -30
```

On the host with Nginx Basic Auth configured:

```bash
curl -u netsecadmin -i https://YOUR_NETSEC_HOSTNAME/api/operator/session
```

Confirm `ok:true` and the configured user. Test unauthenticated HTTPS gets 401 at Nginx, direct upstream privileged request gets 403, and a legitimate UI edit succeeds without another token. Test CrowdSec enforcement separately using a short-lived safe test IP if desired.
