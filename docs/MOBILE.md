# NetSec 1.1.1 — Mobile interface

The same authenticated NetSec dashboard is used on desktop and mobile. At viewport widths at or below 900 CSS pixels, it presents a mobile layout (no separate app, server, login, tokens or additional public port). The original desktop layout is unchanged.

## Phone navigation

- **Home**: at-a-glance read-only traffic risk signal, configured-service health, HTTP request count and 401/403 count; normal sensor health, infrastructure status and map remain below.
- **Jimmy**: evidence-linked conversation, operator feedback and device push notification setup.
- **IPs**: source-IP monitoring, history and drill-down controls.
- **Events**: log filtering and CrowdSec events; recent requests are rendered as labeled cards on narrow displays.
- **More**: Traffic Analytics and Source Intelligence, including operator actions.

Bottom navigation remains visible while scrolling; it respects device safe areas. More can be dismissed by tapping outside or pressing Escape. Existing location hashes and the desktop navigation controller are reused, so push notification links continue to open Jimmy.

## Install on phone

On Android, visit the HTTPS dashboard, authenticate, then choose the browser's Install App/Add to Home screen option. On iPhone, open in Safari, authenticate, choose **Share → Add to Home Screen**, and launch the resulting icon. Notifications are opt-in on each device through **Jimmy → Enable notifications**; Web Push must already be configured on the server.

A regular phone browser shows the mobile layout too. No push-service or CrowdSec changes are required for a UI-only upgrade.

## Upgrade an existing LXC (not a fresh install)

Use the versioned source from the GitHub repository; back up the LXC and host configuration before upgrade. Verify the repo's `VERSION` is **1.1.1** and `bash ci/check.sh` passes. Copy the complete source to the LXC and run the versioned `scripts/install-lxc.sh --upgrade` inside the LXC. It copies new static assets and restarts the dashboard, without changing runtime state or the host-wide Nginx bouncer. Check `docs/MIGRATION.md` for the existing-site warnings and use the full Proxmox backup as rollback.

After deployment, hard-refresh the browser or close and reopen the installed PWA. Verify `/mobile.css` and `/mobile-ui.js` respond with HTTP 200. On mobile, inspect the Home signal against the existing Traffic Security Posture values, navigate all six views, inspect long IPs/path strings, test event filtering and Jimmy form buttons, and verify push notifications still work.

## Privacy and security boundaries

The mobile summary mirrors already-rendered server data. It does not infer a different risk level, perform background requests, export secrets, alter CrowdSec decisions, or change authorization. `mobile-ui.js` delegates navigation to the existing dashboard code. CSS and JS are served from the same authenticated HTTPS site; no external UI dependency is introduced.
