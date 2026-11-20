# NetSec v1.0.2 — From-scratch Proxmox installer

The **v1.0.2 setup wizard** installs NetSec in a **new unprivileged Debian 12 LXC**, optionally provisions a separate HTTPS Nginx site, mounts Nginx logs read-only, optionally installs an independent CrowdSec detection engine, and configures an AI provider and assistant name. The wizard is for the **Proxmox host shell**. It is not meant to run inside an existing LXC.

> **Do not use this on a live NetSec container.** It refuses to replace an existing container ID or Nginx hostname, but Proxmox administrators must review commands and take backups before executing third-party scripts.

## 1. Prerequisites

- Existing supported Proxmox VE host with root shell access, functioning `vmbr0` or another bridge, Internet access, and enough disk space for a new LXC (at least 8 GiB).
- A **free private static IPv4 address** on your LAN, with CIDR prefix (for example `192.168.1.50/24`), gateway and DNS server. Reserve the address in your router and make sure it is not used by another device. Ping alone cannot reliably detect IP conflicts.
- Two active Proxmox storage locations (e.g., `local` for Debian template and `local-lvm` for LXC root disk). A new container ID, e.g. `150`.
- For HTTPS setup: Nginx on the Proxmox host, publicly resolvable hostname pointed at the host, reachable inbound TCP/80 and TCP/443, and `certbot` plus `apache2-utils` on the host. The wizard uses the **HTTP-01 webroot challenge**. When using Cloudflare, set the new record to DNS-only temporarily for issuance, then optionally proxy it using **Full (strict)** TLS.
- For security telemetry: Nginx should write combined-format access logs to `/var/log/nginx/access.log` on the host. This location is mounted **read-only** into the LXC. If you use another path, adapt the config after installation.
- A personal provider credential, if you want AI: an **OpenAI project API key** from https://platform.openai.com/api-keys, or an Open WebUI API key and reachable self-hosted model. **A ChatGPT subscription is not an OpenAI API key or credit.**

### Prepare tools on Proxmox host

```bash
apt-get update
apt-get install -y git nginx certbot apache2-utils acl
```

If your host already has Nginx and TLS configured, the wizard will create a **separate server block and password file**, not overwrite an existing site. Host bouncer configuration is a **separate opt-in** with a new-bouncer/cutover confirmation. On shared Nginx hosts, a cutover affects enforcement for **every** virtual host; leave it unchanged for staging.

## 2. Get the source and run the wizard

```bash
cd /root
git clone https://github.com/kygoodwi108/NetSec.git netsec-source
cd netsec-source
# After v1.0.2 is published, prefer the immutable v1.0.2 tag:
git checkout v1.0.2
bash scripts/proxmox-setup.sh --help
bash scripts/proxmox-setup.sh
```

If v1.0.2 has **not** yet been tagged or merged, use the reviewed v1.0.2 release-candidate archive/branch instead; **do not** run the older v1.0.1 installer expecting these new features.

The wizard asks:

| Setting | Example | Notes |
|---|---|---|
| Container ID / hostname | `150` / `netsec` | Must be unused |
| Static IP/CIDR, gateway, DNS | `192.168.1.50/24`, `192.168.1.1`, `192.168.1.1` | Must match your actual network, not copied blindly |
| Bridge and storage | `vmbr0`, `local`, `local-lvm` | Actual Proxmox resources |
| Assistant name | `Jimmy`, `Sentinel`, `Guardian AI` | Used in UI and AI prompts; 1–32 safe characters |
| AI provider | OpenAI / Open WebUI / None | Cloud provider explicitly opted into |
| AI model | `gpt-4.1-mini` or local model name | Must support Chat Completions with JSON output |
| API key | Private input | **Not printed**; never hard-code a key into GitHub |
| Public hostname and admin login | `netsec.example.org`, `netsecadmin` | Distinct Nginx site and password file |
| Log mount / CrowdSec / timers | opt-in prompts | Read-only monitoring by default; AI timers may incur charges |
| Portable service checks | HTTP(S) URL or TCP host and port | Works for any server, VM or container; no Homepage dependency |
| Nginx CrowdSec bouncer | Keep unchanged / New / Explicit cutover | **Host-wide**; existing config backup and Nginx reload checks |

**Do not paste an API key into GitHub, shell commands, an issue, a chat, or a public configuration.** The installer reads it through a hidden prompt, transfers it via a short-lived root-only file in `/run`, and stores it as `/etc/netsec-ai.env` with group access restricted to `statusdash`. The app reads it as a systemd environment file. On a compromised Proxmox root account secrets can still be read.

## 3. What the installer actually does

1. Validates the requested new LXC ID, private IPv4/CIDR, gateway, disk settings, hostname, assistant name and model. Rejects local-only model identifiers for the OpenAI provider; API key/model validity is confirmed only by a real provider test.
2. Downloads Debian 12 template; provisions a **new** unprivileged container with your static IP; installs Python prerequisites. The installer temporarily uses `umask 0022` during `pct create`, ensuring `/etc` is traversable by `_apt`. It checks `_apt` DNS readiness before APT updates and treats repository failures as errors.
3. Deploys the exact local source checkout, executes `ci/check.sh`, then runs `scripts/install-lxc.sh --fresh` in the new LXC.
4. Writes user-specific `assistant_name` and optional generic `services` checks into `/opt/server-status/config.json`; downloads the offline DB-IP Country Lite database using `statusdash` and enables the monthly refresh timer. An unavailable database is reported as a warning, never a successful map.
5. If AI is selected, stores **your** API key and provider/model details under `/etc/netsec-ai.env`. API requests use either Open WebUI's `/api/chat/completions` or OpenAI's official `/v1/chat/completions` with provider-specific request shaping.
6. Optionally grants read-only access to existing Nginx logs and installs an independent CrowdSec detection engine. Existing host bouncer is left unchanged by default. New bouncer connection/cutover is optional, with an explicit confirmation for host-wide enforcement changes. Always verify a controlled test decision separately.
7. Optionally provisions a separate HTTP/HTTPS Nginx virtual host, a new Basic Auth password file, an HTTP-01 Let's Encrypt certificate, and `/etc/netsec-proxy-auth.json` with IP-pinned proxy authentication.
8. Only enables automated AI timers if explicitly selected **and** a real one-shot AI assessment succeeds; a failed provider credential/model test leaves timers disabled. The manual-ban worker is disabled pending an independently verified bouncer enforcement test.

**The installation can partially succeed before a later step fails** (for example, certificate issuance). Fix DNS, routing or credentials, then complete the remaining steps manually rather than running the new-container wizard again with the same ID. The installer deliberately does not destroy a partially configured LXC. It does not support in-place reinstallations. On Proxmox hosts with production Nginx/CrowdSec, take an independent backup **before** removing an old NetSec container or changing a host bouncer.

## 4. AI privacy, usage and provider choice

**OpenAI:** You provide **your own** API key. NetSec sends bounded security metrics for assessments and source IP/path evidence for auto-labeling to OpenAI, which means some infrastructure information leaves your LAN. The user must explicitly consent. API usage is billed separately from ChatGPT. Choose an appropriate model and monitor usage, especially if recurring classification handles many IPs. Users can disable the timers with:

```bash
pct exec YOUR_CTID -- systemctl disable --now netsec-ai.timer netsec-source-ai.timer
```

**Open WebUI/Ollama:** You provide the origin URL, local model ID and Open WebUI API key. Existing legacy `/etc/netsec-ai.env` files using `OWUI_URL`, `OWUI_KEY`, `OWUI_MODEL` still work. The `NETSEC_AI_*` settings have priority for new installations.

**None:** NetSec functions as an Nginx/CrowdSec dashboard; AI advisory components are not scheduled. Later, create `/etc/netsec-ai.env` based on `config/netsec-ai.env.example` and enable the timers yourself.

**Naming:** Your chosen AI name replaces visible "Jimmy" labels in the served dashboard and is included in the report/AI prompts. It doesn't create a new or privately fine-tuned AI model. Model reasoning and product behaviour remain subject to the selected provider.

## 5. Verify from your Proxmox shell

```bash
CTID=150   # change to your container ID
pct status "$CTID"
pct exec "$CTID" -- systemctl is-active server-status.service
pct exec "$CTID" -- curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/api/status
pct exec "$CTID" -- curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/api/operator/session
pct exec "$CTID" -- bash /root/netsec-setup/scripts/verify.sh
```

Expected dashboard API `200`; privileged endpoint direct to the backend `403`.

If HTTPS was configured:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://netsec.example.org/
curl -u netsecadmin https://netsec.example.org/api/operator/session
```

Expect `401` unauthenticated and `ok: true` with the correct username when signed in. Don't expose the container's port 8787 to the public internet; only the trusted Nginx host should be able to reach it. Verify upstream reachability from your LAN and restrict direct API access with appropriate firewall rules. Keep Proxmox, log ACLs and TLS renewal under ordinary host maintenance.

For AI test without recurring scheduling:

```bash
pct exec "$CTID" -- systemctl start netsec-ai.service
pct exec "$CTID" -- systemctl show netsec-ai.service -p Result -p ExecMainStatus
pct exec "$CTID" -- journalctl -u netsec-ai.service -n 25 --no-pager
```

Expected `Result=success`, `ExecMainStatus=0`; the one-shot service being `inactive` afterward is normal.

## 6. Updates, sharing and recovery

GitHub source and all docs **must not contain** real passwords, private API keys, security logs, or runtime databases. Always back up the LXC before updating, and keep host Nginx sites/certs in a separate private backup. See `docs/MIGRATION.md`. The wizard is only for **brand-new containers**; `scripts/install-lxc.sh --upgrade` is for reviewed upgrades and isn't called by the wizard.

To contribute, fork the public GitHub project, create a branch, run `bash ci/check.sh`, and open a PR. Give users stable version tags and GitHub release assets rather than expecting them to install unreviewed `main`.

## 7. Generic infrastructure service monitoring (no homepage required)

The installer asks whether to configure **read-only direct checks**. Supported probes:

- **HTTP/HTTPS:** a GET to an administrator-selected status URL, e.g. `https://app.example.org/health`. HTTP 2xx–4xx means the web endpoint is responding (401/403 can mean authentication is required); 5xx and connectivity failure are down.
- **TCP:** connect to a specified DNS name/IP and port, e.g. Proxmox web console `192.168.1.10:8006`, a VM's SSH `192.168.1.20:22`, or a service port in an LXC. A successful TCP handshake proves the port is reachable, **not** that the VM is healthy or its application is fully operational.

The checks run inside the new NetSec LXC; confirm its network can reach your target. Checks are parallel and bounded (maximum 25, ~2.5 seconds timeout per endpoint, ~25 seconds cache). No Proxmox administrator token is needed. For a self-signed Proxmox web UI, use **TCP 8006** rather than disabling HTTPS certificate validation. Do not put API keys in service URLs.

After installation, checks are editable in `/opt/server-status/config.json` under `services`:

```json
"services": [
  {"name": "Proxmox Web Console", "type": "tcp", "host": "192.168.1.10", "port": 8006},
  {"name": "Plex Web", "type": "http", "url": "http://192.168.1.30:32400/web"},
  {"name": "Example Site", "type": "http", "url": "https://example.org/health"}
]
```

Restart the dashboard after editing (`systemctl restart server-status.service` inside the LXC). A legacy homepage feed remains optional via `homepage_status_file`, but never needs to be installed or copied for a generic NetSec deployment.

## 8. Optional CrowdSec Nginx bouncer integration

The CrowdSec detection engine and an enforcement **bouncer** are separate. The host installer offers three choices: (1) leave the existing host bouncer unchanged (default), (2) configure a **new** host bouncer when none is configured, (3) explicitly cut over an **existing** bouncer to the new LXC's CrowdSec engine using a typed confirmation.

The new/cutover flow starts a restricted LAPI relay on `LXC_IP:8081` accepting only the Proxmox host IP, uses the official `crowdsec-nginx-bouncer` package, backs up `/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf` in `/root/netsec-bouncer-backups/`, registers a fresh bouncer key, updates the actual main bouncer configuration and validates/reloads Nginx. It refuses to touch a `.conf.local` override with uncertain precedence. If Nginx validation/reload fails, it attempts to restore the previous config.

**Before cutover:** back up the working production container, `/etc/nginx`, `/etc/crowdsec/bouncers`, and the host's active Nginx config. One Nginx bouncer affects **all** hosted sites, not just NetSec. Cloudflare-fronted sites require correctly configured trusted proxy IP parsing so bans apply to real visitors, not Cloudflare edge addresses. Keep existing protection in place when testing staging.

**After registration:** check `cscli bouncers list` and its last pull against the new LAPI. Do not infer enforcement solely from a registered key or successful `nginx -t`; conduct a controlled short-lived block test from a separate, disposable test IP and confirm a denial, then remove the test decision. The first-time installer deliberately leaves the manual ban worker disabled until enforcement is proven.

The installer cannot automatically install CrowdSec bouncers for every server layout (Nginx Proxy Manager, Traefik, Caddy, remote firewalls, etc.). Those remain manual integrations; no existing bouncer is silently replaced.

## 9. Offline country mapping

At install time, NetSec runs:

```bash
runuser -u statusdash -- python3 /opt/server-status/geoip_update.py
```

Monthly refresh is handled by `netsec-geoip-update.timer`. If the initial download fails, the installer warns and the map remains visibly unconfigured until the command succeeds; it never sends visitor IPs to an external lookup service.
