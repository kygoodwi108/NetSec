# PatchMon: fresh standalone installation and NetSec integration

PatchMon is an independent host-patch management platform. **It is not bundled inside NetSec**, and Jimmy never receives PatchMon patch-execution credentials. NetSec uses scoped API credentials for read-only host and package inventory. Installations without a token retain their reachability check.

## Deployment
A guarded helper is included as `scripts/install-patchmon-standalone.sh`. Copy that script to the fresh Debian VM and run `bash install-patchmon-standalone.sh`; it downloads the official setup script for inspection but **does not automatically execute it**. The manual commands below do the same.


Recommended: a **new Debian 12/13 VM** on Proxmox with Docker, separate from the NetSec container (CT 108). A dedicated LXC with Docker nesting configured appropriately may work, but is more complex and has additional isolation considerations. Do not install it on the Proxmox host or inside NetSec LXC 108.

From the console of a **fresh dedicated Debian VM**, as root:

```bash
apt-get update && apt-get install -y ca-certificates curl
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/PatchMon/PatchMon/refs/heads/main/setup-docker.sh \
  -o /root/patchmon-upstream-setup.sh
less /root/patchmon-upstream-setup.sh
bash /root/patchmon-upstream-setup.sh
```

Review the downloaded upstream script before executing it. The upstream setup installs Docker if required, asks for the PatchMon URL and reverse proxy options, sets up /opt/patchmon, and starts the stack. Follow PatchMon's current documentation if the script's prompts or requirements change. **Do not blindly paste a command that pipes remote code into sudo bash.**

Upstream documentation: https://patchmon.net/docs/patchmon-operator-guide/installing-patchmon-server-on-docker

PatchMon includes its own authentication and host enrollment workflow. Create an account and use **PatchMon Hosts → Add host** to obtain its per-host agent install commands. Review the commands before installing agents on your other LXCs or VMs. Do not place agent API keys in NetSec's config or its Git repository.

## Optional reverse proxy

If exposing it through the existing Proxmox Nginx reverse proxy, use a *new*, HTTPS-protected hostname with a dedicated server block and valid certificate, pointing to the VM's private address and the port shown by the PatchMon setup script (typically 3000). Ensure WebSocket support if required by the selected PatchMon features. Do not modify the working NetSec/PVE virtual hosts. The prior manual PatchMon proxy used forwarded-proto/host headers, WebSocket Upgrade, buffering disabled and a long read timeout. A reviewed, **opt-in** Nginx location example is now in `examples/nginx-patchmon-location.conf`; adjust the upstream IP and test against your existing Certbot-managed server block. Do not duplicate its TLS listener or remove its CA+US host GeoIP gate.

## Connect its availability status to NetSec

In the **NetSec LXC** edit `/opt/server-status/config.json` and set:

```json
"patchmon_url": "http://192.168.2.X:3000"
```

Replace X with the actual private address of the dedicated PatchMon VM. Add this key **inside the existing top-level JSON object**, separated by commas as needed. It must be HTTP or HTTPS to a **private IP literal**, with no credentials, query string or path. Use an HTTPS URL only when the certificate is valid for its address.

Validate and restart NetSec (inside NetSec LXC, not on the Proxmox host):

```bash
python3 -m json.tool /opt/server-status/config.json >/dev/null
systemctl restart server-status
systemctl is-active server-status
```

Open Command Hub to see availability. For host inventory, run
`netsec-patchmon-configure` as root inside NetSec. Supply the hostname on the
PatchMon TLS certificate, the private proxy IP listening on 443, and a
PatchMon API token scoped to `host:get`. The helper atomically saves these
settings in /etc/netsec-patchmon-readonly.json (root:statusdash, 0640).
The standalone hotfix's existing credential file is preserved on upgrade.
Its original hostname and proxy IP are recovered from the installed module
before replacement. Reachability-only installations can continue without a token.

Command Hub shows pending packages, security updates, stale agents and reboot
indicators. Jimmy receives a bounded summary from the same read-only API.
An HTTP 401 or 403 from that API appears as access denied. The client verifies
the certificate and sends credentials only to the configured TLS endpoint.
