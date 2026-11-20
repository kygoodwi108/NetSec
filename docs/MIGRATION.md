# Recovery, migrations and upgrades

## What the public source ZIP does and does not contain
The ZIP contains **every reconstructed v1.1.1 application module, static asset, service file and setup script**. It is re-installable on a new Debian LXC with external Proxmox/Nginx/CrowdSec configuration.

It deliberately **does not** contain your live IP labels, history SQLite databases, source AI classifications, CrowdSec ban decisions, private API keys, the `netsecadmin` password file, certificates, Nginx site files or personal runtime configs. These are operational state and secrets and must **never** go into Git.

## Before rebuilding an existing server
1. Take a Proxmox `vzdump` backup/snapshot of your live LXC. Preserve the Proxmox host's Nginx configuration and certs in a **separate private backup**. LXC backups do not automatically include host-mounted Nginx logs.
2. Export NetSec state **privately** while the service is quiesced if possible (SQLite consistency): `bash scripts/backup-state.sh /root/netsec-private-state-$(date +%F).tar.gz` inside the LXC. Store it securely offline; it has secrets. Also record `pct config YOUR_CTID` and currently installed systemd overrides.
3. Rebuild on a **separate test LXC** from this ZIP using `docs/INSTALL.md` and its own private address/hostname. Check Nginx log permissions and authenticated actions before moving traffic.
4. Restore private state only from your own trusted backup and only after stopping app and AI workers. Inspect paths and ensure account UID/GID match; use `tar -tzf` first, then restore securely as root. Move `/var/lib/server-status` ownership as required, preserving root-owned exported files. Restore exact `/etc/netsec-*.json` and private Open WebUI API env as appropriate; don't blindly carry old proxy IP settings to a new host.
5. Verify services, audit logs, source labels, recent reports, manual ban flow, full-scan state and dashboard authentication. CrowdSec LAPI decisions are **not** automatically reproduced by copying NetSec's own data directory.

## Upgrading your existing NetSec 3.8.5 personal LXC
This release was **reconstructed** from the uploaded patch chain, including a tested staged 3.8.5 tree, but not read directly off the live container. There may be local edits, extra drop-ins, or services missing from this archive's staging environment. **Do not run a blind upgrade on your production LXC.** Prefer exporting current `/opt/server-status` and `/etc/systemd/system` first and diffing against this tree.

For a verified test clone only:

```bash
# Inside test LXC, after snapshot + manual backup:
bash scripts/install-lxc.sh --upgrade
```

`--upgrade` backs up current `/opt/server-status` and key config files to a root-only directory and does not overwrite existing `config.json`, operator profile or secret env files. It **does not** snapshot your ongoing SQLite state, including `jimmy-workspace.sqlite3` or host Nginx configuration. It replaces the installed systemd unit definitions and restarts the app; inspect existing site-specific drop-ins first. Keep the full Proxmox backup as the primary rollback method.

## NetSec v1.1.0 release handoff
A new chat can start by uploading this ZIP and saying: "Continue NetSec v1.1.0; read docs/PROJECT_HANDOFF.md and docs/INSTALL_FROM_SCRATCH.md. Test the Jimmy PWA/chat/push on a safe staging instance before production cutover." The next chat does not require the entire old conversation to understand the project structure. For any new release, provide a complete Mac-to-Proxmox-to-LXC remote installation and rollback procedure.

## NetSec 1.1.0 → 1.1.1 UI-only upgrade

Version 1.1.1 introduces mobile presentation assets and static file routing; no database schema, push keys, Nginx site or CrowdSec bouncer changes. The `--upgrade` script supports the installed 1.1.0 signature and retains `config.json`, operator context, credentials, and `/var/lib/server-status`. It still replaces NetSec systemd units and restarts the dashboard: take a verified `vzdump` first, preserve host Nginx/bouncer configuration separately, and confirm scheduled services afterward.

To install from GitHub, first `git pull --ff-only origin main` into a clean Proxmox source checkout after publishing the verified 1.1.1 files, verify `cat VERSION` and `bash ci/check.sh`, then tar excluding `.git`, checksum/`pct push` it to the intended LXC and extract in `/root`. Run `bash scripts/install-lxc.sh --upgrade` inside that extracted root. See `docs/MOBILE.md` for UI verification and `docs/INSTALL_FROM_SCRATCH.md` for fresh LXC paths. Do not use `scripts/proxmox-setup.sh` to update an existing CTID.
