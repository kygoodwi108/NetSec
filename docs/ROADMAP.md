# NetSec roadmap — 1.1.0 and beyond

## 1.1.0 release-candidate features implemented (live deployment verification pending)
- Dedicated **Jimmy Analyst** tab with detailed calibrated assessment, preserved Command Hub summary, assessment-linked Ask Jimmy chat and local conversation history.
- Authenticated operator feedback actions: I confirm, That is expected, I own this IP, I disagree, Maintenance until; author/time/expiry/audit provenance; read-only inclusion in future model prompts; calibrated severity retains its independent evidence basis.
- Installable PWA manifest, icons, service worker with **generic offline page only** (never cached authenticated security data), responsive Jimmy workspace and phone controls.
- Authenticated, opt-in Web Push browser subscriptions; manual VAPID key rotation; one notification on new evidence-calibrated red event, repeated-red suppression, acknowledgements, quiet periods, optional single delayed escalation, delivery self-test and invalid subscription cleanup.
- Service setup prompts revised to avoid unintentionally skipping checks; generic HTTP/TCP checker is now usable as fresh verified reachability evidence in Jimmy.
- Automated unit tests for chat persistence, feedback expiry, CSRF/proxy auth, Web Push endpoint filtering, red incident dedup and static PWA wiring.

**Not yet validated:** full Proxmox clean-install with host CrowdSec bouncer cutover, VAPID delivery to real iOS and Android phones, full production traffic/Cloudflare integration. A passing offline test is not a live integration guarantee.

## Safety boundaries (required)
- No arbitrary shell execution, no command execution through Jimmy chat, no autonomous bans or firewall changes.
- Operator context is **unverified**, separate from actual observed telemetry; manual source labels win, original evidence is preserved, and friendly metadata does not disable CrowdSec blocking.
- Authenticated same-origin operator writes remain pinned to the trusted Nginx host and checked against origin/host; direct LXC API writes fail closed.
- Public repository never contains real API keys, real VAPID private keys, host Nginx passwords, or client source IP histories.
- A bouncer registration/last pull is not evidence of an actual blocked HTTP request; verify enforcement separately before any cutover.

## Later priorities
- User-facing service settings editor and self-discovery with explicit approvals (not an automatic assumption of VM health).
- Multiple operator accounts/roles and per-user notification subscriptions and audit filtering.
- Deeper browser and mobile integration testing, native push delivery monitoring and end-to-end incident replay.
- Dedicated on-device voice is **not** promised; no EDR/SSH packet capture or SMS/native iOS app in 1.1.0.
