# NetSec Roadmap — after v1.0.1

> **Not implemented in v1.0.1.** This document captures the next agreed iteration; do not represent it as shipping functionality.

## Priority 1 — Jimmy Analyst workspace (new dedicated tab)
- Move the existing detailed security assessment, evidence-driven severity, deterministic investigations, sensitive-path checks, model uncertainty, and historical context **out of the current dashboard overview** and into a dedicated **Jimmy** tab. Retain an overview severity/last-updated summary on the home screen.
- Add an **Ask Jimmy** conversation panel anchored to a specific assessment ID/time, backed by the existing local Open WebUI/Ollama model. Questions such as why a 500 spike was classified as red must reference actual available evidence and explicitly identify missing evidence.
- Use bounded, pre-approved read-only evidence retrieval functions; no model-authored shell commands, no command execution, no configuration edits, no autonomous bans.
- Distinguish **observed telemetry** / **operator-supplied context** / **AI inference** and expose sources and timestamps. Retain a local conversation history in `/var/lib/server-status` (not in Git).

## Priority 2 — Operator feedback loop
- Provide "I confirm", "That is expected", "I own this IP", "I disagree", "maintenance until..." actions plus a free-text response in Jimmy's tab.
- Store structured operator feedback with origin, scope, author, timestamp, TTL/expiry and audit trail; separate permanent friendly/owned IPs from temporary maintenance explanations.
- New assessments incorporate operator context without rewriting log facts or elevating an assertion to independently verified evidence. Give explicit before/after severity reasoning when feedback changes interpretation.
- Manual labels override Jimmy labels; Jimmy may flag unusual behaviour but cannot silently remove trusted ownership. Labeling must never automatically ban an IP.

## Priority 3 — Installable mobile web app (PWA)
- Responsive navigation with web-app manifest and icons, service-worker offline shell, stable HTTPS origin, Add to Home Screen instructions.
- PWA supports the full dedicated Jimmy tab, chat, review/acknowledge and saved operator feedback from a phone. Preserve existing Nginx-authenticated `netsecadmin` workflow (not a separate recurring token).
- Browser Web Push subscription registration, opt-in permission, subscription invalidation, server-side push delivery with rotating VAPID keys and no secret telemetry in notification body. On iPhone, Home Screen installation and system support are prerequisites; do not assume push works merely because a website is open in Safari.
- Send push on **new evidence-calibrated red incidents or escalation**, not every scheduled red refresh; de-duplicate via event fingerprint, include acknowledgements/quiet periods and optional escalation if a significant incident is unacknowledged.
- Notification opens the exact Jimmy report, requiring authenticated HTTPS session to access details. Support notification self-test and delivery monitoring.

## Acceptance criteria
1. Mobile PWA installable from HTTPS, working on current Android and supported iOS; browser sessions still require normal authentication.
2. Newly verified red event sends one actionable notification, not a flood; previously red stays quiet unless new evidence or escalation occurs.
3. Operator feedback changes context/assessment only with recorded evidence provenance and can expire.
4. Both chat and feedback are strictly advisory; no AI-generated CrowdSec bans or arbitrary commands.
5. Public repo contains no site keys, real hostnames, secrets or personal traffic data; community installation uses independent credentials and configurable hostnames.
6. Tests cover trusted proxy controls, cross-origin writes, malformed AI replies, red deduplication, notification subscription security, and audit/event replay.

## Deferred / not promised
- Full autonomous penetration testing, honeypots, host EDR, SSH packet monitoring, SMS alerts or native iOS app are **not** part of the agreed next feature.
- Mobile conversations through Telegram/ntfy are not currently planned; the chosen direction is NetSec's own web app.
