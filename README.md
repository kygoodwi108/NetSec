 NetSec v1.0.1

Self-hosted security dashboard for Nginx + CrowdSec on Proxmox/Debian, with **Jimmy**, a local Open WebUI/Ollama-backed advisory analyst. This release is the **consolidated application source**, not another incremental upgrade patch.

**Status:** offline-integrated source distribution. Unit/syntax tests run locally; no end-to-end validation against a new Proxmox host or the live existing LXC has been performed. See `docs/INSTALL.md` before deployment. Not a guarantee of security.

## Features included today

| Component | In v1.0.1 |
|---|---|
| Nginx HTTP traffic, countries, response metrics, connection and scan views | Yes |
| CrowdSec alerts, bouncer/decision metadata and deterministic checks | Yes, when CrowdSec and log access configured |
| Operator authentication through Nginx Basic Auth / verified user forwarding | Yes (no separate dashboard admin token) |
| Source Intelligence with AI advisory labels and manual overrides | Yes; labels do **not** ban |
| Jimmy model assessments, retry handling, calibrated severity and evidence | Yes, local model optional |
| Opt-in preauthorized sensitive-path probes | Yes; disabled/full scan requires verified allowlist |
| Manual, explicitly authorized CrowdSec bans | Yes; separate root worker |
| Mobile PWA, Jimmy chat, operator assessment feedback, push notifications | **Not yet** — roadmap only |

## Repository structure

```text
app/             Application modules, static dashboard and data assets
systemd/         Services, timers and path activations
scripts/         Installer, private-state backup, verification, host/CrowdSec helpers
config/          Safe, non-operational examples; secrets NOT included
examples/        Nginx examples; never overwrite your existing proxy automatically
ci/, tests/      Offline unit tests and static checks
docs/            Fresh install, upgrades, data migration, architecture, roadmap, handoff
VERSION          1.0.1
LICENSE          MIT
```

## Quick start for a **new, empty** Debian 12 LXC

1. Prepare a container with Python 3, Nginx log bind mount and network connection as described in `docs/INSTALL.md`.
2. Copy this extracted project into the LXC, `cd netsec-v1.0.1`, then run `bash scripts/install-lxc.sh --fresh` **inside** the LXC.
3. Configure `/opt/server-status/config.json` and the separately required `/etc/netsec-proxy-auth.json` (trusted proxy IP, username and HTTPS origin).
4. On the **Proxmox host**, configure authenticated HTTPS Nginx proxy to the LXC; see `examples/nginx-location.conf` and `docs/INSTALL.md`.
5. Install/configure CrowdSec separately and set up read-only log access. Optionally add `/etc/netsec-ai.env` for local Open WebUI and enable AI timers.
6. Run `bash scripts/verify.sh`; test `/api/operator/session` through the **authenticated** HTTPS hostname and test a manual friendly label.

**Upgrade/rebuild:** `docs/MIGRATION.md` first. The default `--fresh` installer refuses to overwrite a preexisting NetSec. `--upgrade` is explicit and backs up installed application/config, but is not a replacement for a full LXC backup or tested migration.

## Security model

- Nginx **authenticates** users, then sets `X-NetSec-Authenticated-User $remote_user` before proxying. The backend verifies the request's **TCP source IP** against the configured trusted proxy and verifies the user and same-origin write headers.
- It strips `Authorization` before sending requests to Python. Do not remove Nginx authentication or expose the NetSec backend listener to untrusted networks.
- The AI is advisory only. Manual ban action uses an authenticated queue and a separately validated root worker; normal source labeling does not alter CrowdSec decisions.
- Outbound model telemetry, if enabled, is sent to the operator-configured Open WebUI endpoint. Keep that endpoint local/private and secure; never commit credentials.

## For contributors

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q app
```

See `CONTRIBUTING.md` and `docs/PROJECT_HANDOFF.md`. Do not commit data under `/var/lib/server-status`, `/etc/netsec-ai.env`, real Nginx configuration, a trusted-proxy token, or any security logs.
