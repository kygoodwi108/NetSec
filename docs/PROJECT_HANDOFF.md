# NetSec 1.1.0 — project handoff

## State
- Full standalone source archive, based on the verified 1.0.2 installer refinement and legacy 3.8.5-derived application. Version reset is deliberate: current semantic version **1.1.0**.
- **Release candidate.** Offline regression and local HTTP tests passed; live Proxmox, installed mobile app, browser push providers and host Nginx CrowdSec cutover have not yet been validated together. Do not call it production verified.
- Never embed user keys, Nginx passwords, TLS keys, real IP histories, or VAPID private keys in published repository files.

## Implemented
- Command Hub, traffic and source intelligence tabs; evidence-calibrated Jimmy read-only Nginx/CrowdSec diagnostics; manual source metadata; optional controlled CrowdSec bans with operator auth.
- Dedicated **Jimmy Analyst** tab: report ID/time, severity and evidence source limitations, persisted Ask Jimmy conversation, structured operator feedback (confirm/expected/own-IP/disagree/maintenance) with audit/TTL, and subsequent AI context. Operator assertions cannot override verified telemetry, and AI cannot generate actions or bans.
- PWA manifest and icons, privacy-protecting offline page, responsive mobile workspace, authenticated opt-in Web Push, safe browser endpoint validation, private VAPID keys, red incident dedup, quiet periods, acknowledgement and optional single delayed escalation.
- Generic HTTP/TCP service checks and automatic offline country database in host installer; optional separate CrowdSec LXC engine and explicit new-bouncer/cutover choices. Known Proxmox umask 077 → `/etc` mode 700 bug corrected during LXC create.

## Files and services
- App `/opt/server-status`, state `/var/lib/server-status` including `jimmy-workspace.sqlite3`, AI config `/etc/netsec-ai.env`, proxy auth `/etc/netsec-proxy-auth.json`, diagnostics `/etc/netsec-diagnostics.json`.
- Push private identity `/etc/netsec-push.json` and `/etc/netsec-push-private.pem`, optional Python venv `/opt/netsec-push-venv`, timer `netsec-push.timer`.
- CLI `scripts/proxmox-setup.sh` only from Proxmox host; manual in-LXC installer `scripts/install-lxc.sh --fresh|--upgrade`.

## User's deployment testing convention
- Preserve existing working production LXC and remote public HTTPS admin access while testing replacement on a separate static-IP LXC. Host-wide bouncer changes are opt-in and backed up; keep old CrowdSec LAPI available for rollback until new enforcement is actually confirmed.
- Provide **complete** Mac-to-host (normal SCP or temporary `curl -T ... https://qurl.sh` when remote), SHA-256 check, host/LXC `pct push` and extraction, full installation, verification and rollback instructions for every release.
- Do not assume everything about personal `108`/`150` paths or credentials applies to other users.

## Next validation
Run full clean Debian 12 Proxmox installation, test configured services/GeoIP, one real Open WebUI assessment + Ask Jimmy, operator feedback before/after, PWA installation and push self-test on physical phone, stable red dedup, Nginx bouncer last pull and controlled external 403 block. Then sign/tag the published GitHub release. See `docs/INSTALL_FROM_SCRATCH.md`.
