## v1.1.0 — Jimmy Analyst workspace, PWA, Web Push (release candidate)

- Moved full evidence-calibrated Jimmy assessment to a separate **Jimmy Analyst** tab, preserving the Command Hub's live overview and brief analyst severity summary.
- Added authenticated assessment-ID-linked Ask Jimmy conversations; durable, bounded local SQLite history and read-only, cited/timestamped evidence context. No arbitrary tool calls, shell commands or AI bans.
- Added operator feedback (confirm, expected, own-IP, disagree, maintenance), audit timestamps, expiry and safe reuse in subsequent AI model prompts; deterministic severity is **not** overridden by operator assertions.
- Added mobile PWA manifest/icons with generic offline fallback. No authentication data, logs or model replies are cached by service worker.
- Added optional pywebpush backend with private rotating VAPID identity, validated browser subscriptions, red incident deduplication, acknowledgement, quiet hours, optional one-time escalation and a delivery test.
- Updated built-in HTTP/TCP monitoring to feed Jimmy's freshness checks (not just the former homepage feed).
- Improved first-run service monitor instructions and final configuration summary; explicit warning when none configured. Retains first-boot DNS/umask, GeoIP, AI test and optional host bouncer setup fixes from 1.0.2.
- Added new unit tests and a local HTTP smoke test. **Live Proxmox host-bouncer cutover and real-device Web Push delivery remain unverified.**

## v1.0.2 installer refinement (release candidate)

- Fixed unprivileged Debian APT DNS failure during Proxmox LXC creation: container-creation umask is 0022 only in a subshell, and `_apt` DNS readiness is verified before strict/retried APT updates.
- Automatic offline DB-IP country database initialization and monthly refresh timer; download failures are reported without falsely marking GeoIP ready.
- Portable generic HTTP(S) and TCP endpoint checks configure directly in the wizard. No dependency on an author's homepage; the old homepage integration remains optional.
- Opt-in CrowdSec Nginx bouncer registration or explicit host-wide cutover (defaults to no change). Retains backup and rollback, refuses unexpected override configs, does not claim enforcement before a verified test.
- Added optional one-shot AI provider test, host-specific diagnostics, provider-family guard against local model names on OpenAI, and regression tests.

# Changelog

Version history is intentionally renumbered for the consolidated, future public Git repository.

## v1.0.2 — Candidate: first-time onboarding (not yet live host validated)
- Added interactive Proxmox host installer with configurable private static IP/CIDR, gateway, DNS, storage, independent hostname, and optional HTTPS + Nginx Basic Auth.
- Added choice of operator-owned OpenAI API key or local Open WebUI/Ollama key, model and an assistant display name. No credentials are bundled.
- Added OpenAI Chat Completions transport adapter, retaining legacy Open WebUI settings; local model compatibility is preserved.
- Added staging-safe CrowdSec detector-only setup; no production host bouncer or automatic-ban activation.
- Added from-scratch installation, privacy and billing documentation; tests cover provider request mapping and safe naming.
- New first-run wizard has **not** been validated end-to-end on a Proxmox host. Test in a new LXC; v1.0.1 remains the validated baseline.

## v1.0.1 — 2026-11-20 — Consolidated source release
- First complete **personal-feature** source distribution reconstructed from the legacy dashboard upgrade chain (through internal 3.8.5); does **not** require replaying the earlier patch ZIPs.
- Includes Nginx analytics, CrowdSec evidence/exports, Source Intelligence Hub, AI advisory source labels, manual labels, read-only Jimmy diagnostics, operator-authenticated ban queue, and evidence-calibrated JSON assessment path.
- Consolidates Debian LXC install scripts, systemd units, example configs, tests, security and migration docs, plus Git-ready source layout.
- Replaces hard-coded personal proxy hostname with operator-specific `/etc/netsec-proxy-auth.json`. Advisory email link configurable with `NETSEC_PUBLIC_URL`.
- Existing detailed Jimmy assessment remains in its current UI location. **PWA, chat, feedback loop and phone push notifications have not been built.** They are in `docs/ROADMAP.md`.
- **Distribution caveat:** recreated from supplied archives and staged build sources, not exported from the running server. Installed environment differences must be reconciled before an upgrade.

## Legacy development line (historical; not current semantic version numbers)
- 3.8.5: token-free authenticated operator actions and evidence-calibrated assessment (3.8.4 preflight fix).
- 3.8.3: opt-in authorized multi-path deterministic probes.
- 3.8.2: separated application token header from HTTP Basic Auth.
- 3.8.1: first auth hotfix with overly narrow patch precondition (superseded).
- 3.8: proactive advisory source classification and full manual source labeling.
- 3.7.1: AI JSON resilience; 3.7: deterministic evidence-led investigation.
- 3.6: manual ban worker and diagnostics; 3.5: Command Hub; 3.4: Jimmy context.
- 3.3: homepage bridge; 3.2: AI/manual refresh reliability; 3.1: incident evidence; 3: Source Intelligence; 2: core dashboard.

## Semantic versioning rule from here
- `MAJOR`: incompatible migrations, `MINOR`: backwards-compatible functionality, `PATCH`: fixes and packaging improvements.
- Next feature changes after 1.1.0 use a new SemVer release; do not silently modify a published tag.
