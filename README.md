# NetSec v1.0.2

Self-hosted security dashboard for Nginx + CrowdSec on Proxmox/Debian, with a configurable AI security analyst supporting either **your own OpenAI API key** or a local **Open WebUI/Ollama** model. This release is the **consolidated application source**, not another incremental upgrade patch.

**Status:** v1.0.1 passed an independent fresh Debian 12 LXC integration test (dashboard, HTTPS, CrowdSec observation and Jimmy). The new v1.0.2 first-time installer/host automation remains **not yet validated end-to-end on a Proxmox host**. See `docs/INSTALL_FROM_SCRATCH.md` before deployment. Not a guarantee of security.

## Features included today

| Component | In v1.0.2 |
|---|---|
| Nginx HTTP traffic, countries, response metrics, connection and scan views | Yes |
| CrowdSec alerts, bouncer/decision metadata and deterministic checks | Yes, when CrowdSec and log access configured |
| Operator authentication through Nginx Basic Auth / verified user forwarding | Yes (no separate dashboard admin token) |
| Source Intelligence with AI advisory labels and manual overrides | Yes; labels do **not** ban |
| AI assessments, retries, calibrated severity and evidence | Yes; OpenAI API or local Open WebUI/Ollama; API key supplied by operator |
| First-time Proxmox installer: static IP, hostname, AI name, private key, optional authenticated HTTPS | Yes; new containers only |
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
VERSION          1.0.2
LICENSE          MIT
```

## New installations — guided Proxmox wizard

Review **[`docs/INSTALL_FROM_SCRATCH.md`](docs/INSTALL_FROM_SCRATCH.md)**. Run this from a *new checkout on your Proxmox host*, not inside an existing container:

```bash
bash scripts/proxmox-setup.sh --help
bash scripts/proxmox-setup.sh
```

The wizard prompts for static private IP/CIDR, gateway, DNS, LXC ID, bridge/storage, assistant name, OpenAI API or local Open WebUI/Ollama, model, a hidden **user-owned API key**, and optional authenticated HTTPS hostname. It never copies the author's key; v1.0.1 had no project-distributed runtime secrets. With OpenAI, security telemetry leaves your network and usage is billed separately; this choice requires explicit consent. The wizard refuses an existing container ID or Nginx hostname. It initializes offline IP-country mapping, includes generic HTTP(S) and TCP service checks (no personal homepage required), and provides an **explicitly optional** Nginx bouncer registration/cutover with a backup. Host-wide enforcement defaults to unchanged.

Manual Debian LXC deployment is still supported; see [`docs/INSTALL.md`](docs/INSTALL.md). Upgrade/recovery procedures are in `docs/MIGRATION.md` and require an independent LXC backup.

## Security model

- Nginx **authenticates** users, then sets `X-NetSec-Authenticated-User $remote_user` before proxying. The backend verifies the request's **TCP source IP** against the configured trusted proxy and verifies the user and same-origin write headers.
- It strips `Authorization` before sending requests to Python. Do not remove Nginx authentication or expose the NetSec backend listener to untrusted networks.
- The AI is advisory only. Manual ban action uses an authenticated queue and a separately validated root worker; normal source labeling does not alter CrowdSec decisions.
- Outbound model telemetry, if enabled, is sent to the operator-configured **OpenAI API or Open WebUI** endpoint. Selecting OpenAI sends security-derived data outside your LAN; never commit credentials. Neither the maintainer nor another end user supplies the key.

## For contributors

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q app
```

See `CONTRIBUTING.md` and `docs/PROJECT_HANDOFF.md`. Do not commit data under `/var/lib/server-status`, `/etc/netsec-ai.env`, real Nginx configuration, a trusted-proxy token, or any security logs.
