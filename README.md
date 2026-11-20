# NetSec v1.1.1 — Proxmox security dashboard and Jimmy analyst

**Release candidate — full fresh install and real-device Web Push tests pending.** Source includes the NetSec 3.8.5-derived security dashboard, generic server monitoring, evidence-calibrated local/cloud AI, optional independent CrowdSec engine and host bouncer, and a mobile-ready Jimmy analyst workspace.

## Get started

Start with **[the complete Proxmox fresh-install guide](docs/INSTALL_FROM_SCRATCH.md)**. The automated wizard runs as root on the **Proxmox host** from the extracted release source, creates a **new Debian 12 unprivileged LXC**, and refuses to overwrite an existing CT or Nginx virtual host:

```bash
cat VERSION                 # 1.1.1
bash ci/check.sh
bash scripts/proxmox-setup.sh --help
bash scripts/proxmox-setup.sh
```

**Before a live replacement:** Back up the LXC and the host's Nginx/HTTPS/CrowdSec configuration separately. A bouncer cutover affects **all** Nginx sites on the host; default is leave it unchanged. Do not delete a known-good installation merely because offline tests pass.

## What's in 1.1.1

- Command Hub, traffic logs, source intelligence, IP connection outcomes, geography, CrowdSec telemetry and operator-controlled manual labels.
- Independent HTTP(S) and TCP service checks for generic Proxmox, VM, LXC, container, and website deployments. No special homepage feed required.
- Offline GeoIP initialization plus monthly refresh timer (the address database is downloaded during install, not distributed as a bundled private asset).
- Detailed **Jimmy Analyst** tab: report IDs, timestamps, observed evidence, deterministic calibration, limitations, assessment-linked chat with local history.
- Authenticated operator feedback including verified ownership metadata, maintenance notes, TTL, and audit trail. Feedback is explicitly **operator-supplied context**, not forensic evidence; it cannot autonomously ban.
- PWA manifest/icons and an offline information page. Authenticated telemetry and chat are always network-only.
- Opt-in Web Push notification subscriptions, VAPID-key rotation, deduped calibrated-red incidents, quiet periods, acknowledgements and optional one-time escalation.
- AI provider choice: local Open WebUI/Ollama or user-owned OpenAI API key/model. ChatGPT subscriptions are not API credentials; OpenAI may incur separate usage charges.
- Native Debian LXC systemd services. No Docker required for the dashboard; no preloaded personal credentials or log data.

## Security model

The dashboard operates behind HTTPS Nginx Basic Auth. Sensitive writes additionally require a trusted proxy source, verified username, same-origin checks and action headers. The backend deliberately does not issue model-generated shell commands, silent bans, or firewall changes. CrowdSec bouncer enforcement is optional and independently verified; reading access logs does **not** by itself block anyone.

Source ZIPs must not include private runtime state or secrets. Web Push delivery uses browser push services; notification payloads contain a generic finding notice and report link only (no IPs, log lines or model responses). The private VAPID key resides in `/etc/netsec-push-private.pem` on the target machine.

## Project files

| Location | Purpose |
|---|---|
| `scripts/proxmox-setup.sh` | Interactive brand-new LXC + Nginx + optional CrowdSec/push wizard |
| `scripts/install-lxc.sh` | Fresh/upgrade app deployment inside Debian LXC |
| `app/app.py` | Bounded HTTP log API and dashboard, authenticated operator routes |
| `app/netsec_jimmy_api.py` | Evidence-linked chat and operator-feedback API |
| `app/netsec_jimmy_store.py` | Local SQLite audit/history/subscription state |
| `app/netsec_push.py` | Optional deduplicated red-incident Web Push dispatcher |
| `app/jimmy-ui.js`, `app/sw.js` | Mobile Jimmy workspace and privacy-preserving offline shell |
| `systemd/` | Native systemd services and timers |
| `docs/INSTALL_FROM_SCRATCH.md` | Full setup, remote file transfer, checks, bouncer safety and rollback |
| `docs/ROADMAP.md` | Implemented features, pending live verification and exclusions |

Run `bash ci/check.sh` before publishing or deploying changes. **There is no representation here that v1.1.1 has passed a complete host-wide bouncer cutover or real-device Web Push test yet.**

## Phone layout (v1.1.1)

At narrow screen widths, NetSec keeps the existing data and actions, but presents a quick telemetry summary, bottom navigation with Home/Jimmy/IPs/Events/More, and labeled event/IP cards instead of forcing seven-column tables to fit. The desktop view is unchanged. No account settings or server-side migration are needed; refresh the installed PWA after an upgrade. See `docs/MOBILE.md` for use and testing.
