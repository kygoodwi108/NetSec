# Changelog

Version history is intentionally renumbered for the consolidated, future public Git repository.

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
- Next proposed functionality should use **v1.1.0** unless the scope merits a breaking release.
