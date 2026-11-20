# Project handoff — NetSec v1.0.2 (for another conversation or contributor)

## Intent
- Standalone, Git-ready project release built by consolidating the personal NetSec 3.x patches through internal **3.8.5**. Public baseline version was **1.0.1**; this onboarding update is **1.0.2**, with future versions using SemVer.
- This ZIP is the **entire reconstructed source project**, not a patch. Legacy patch ZIPs should not be needed for a clean rebuild.
- No credentials, personal runtime logs, live AI assessments or source IP lists included. Real deployment config stays private.

## Existing functionality
- Multi-tab dark dashboard: web request/status, source intelligence, commands, per-IP traffic, CrowdSec enforcement.
- Jimmy local model assessments with structured retries, deterministic Nginx error/bouncer checks, opt-in sensitive-path probes, evidence-calibrated risk, manual refresh.
- Proactive source labeling from AI; manual Friendly/Hostile/Watch etc classifications. AI labels are for presentation/filtering and cannot autonomously ban.
- Manual root-worker CrowdSec bans require a verified reverse-proxy authenticated user and explicit operator action, no additional admin token. Configurable IP-pinned reverse proxy auth in `/etc/netsec-proxy-auth.json`.
- Native Debian LXC services and exports, optional Open WebUI and CrowdSec.

## Important production history
- Token vs Basic Auth `Authorization` header collision previously caused repeated browser login prompts; current app sends `X-NetSec-Action: dashboard` and Nginx forwards a verified username using `X-NetSec-Authenticated-User` while removing the Basic Auth `Authorization` header.
- Some historical hotfixes failed preflight due to exact-code-string mismatch. Prefer versioned source deployment and semantic regression tests, not cumulative `str.replace`-based patches.
- Risk evaluator used to report unsupported red alerts for successful CrowdSec denials and bounded upstream log errors. Current evidence-calibrated risk path separates defense activity, operational issues and compromise evidence.
- Full-scan diagnostics were limited to one path per six hours before authorized mode; current opt-in path can cover configured hosts with a verified narrow CrowdSec probe-source allowance.

## Next product request (NOT IMPLEMENTED)
User selected a **NetSec installable mobile web app (PWA)** rather than Telegram/ntfy chat. Move Jimmy's **detailed security assessment to its own dedicated tab** and integrate contextual Ask Jimmy conversations, bidirectional operator feedback that influences subsequent assessments, and push alerts on new evidence-confirmed red incidents. Keep overview risk summary. See `docs/ROADMAP.md` for complete feature and acceptance definition.

## Operational conventions
- Main source `/opt/server-status`, data `/var/lib/server-status`, credential env `/etc/netsec-ai.env`, diagnostics `/etc/netsec-diagnostics.json`, auth policy `/etc/netsec-proxy-auth.json`.
- On Proxmox, a common personal layout uses Debian LXC **108** with Nginx reverse proxy on host and CrowdSec in LXC; this ID is deployment-specific, not part of the public source code.
- User may be **away from home**. New release instructions must include direct ZIP download, Mac upload to a temporary HTTPS link if SSH isn't reachable, host curl retrieval and checksum, `pct push` and extraction in LXC, backup, install and systemd checks. Never assume workstation can reach 192.168.x LAN.
- Keep remote HTTPS access. Do not automatically insist on VPN-only administration or shutting off Proxmox public access as default.
- Source of truth: code and docs in this archive. Validate against live system before claiming production parity; don't infer private config from example files.

## v1.0.2 onboarding additions
- New `scripts/proxmox-setup.sh` interactive host installer for static private IPv4/CIDR, gateway, DNS, LXC ID, template/storage, HTTPS Basic Auth, AI assistant name, and personal provider key.
- New cloud OpenAI API or local Open WebUI/Ollama provider compatibility via `app/netsec_ai_provider.py`; cloud telemetry requires explicit consent.
- No preconfigured author API credentials; source archive contains examples only.
- The host installer is offline-checked but not yet live Proxmox end-to-end tested. Never assume v1.0.2 is validated solely because v1.0.1 was.
