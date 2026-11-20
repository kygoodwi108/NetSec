# Security policy and deployment warnings

This is a self-hosted security visibility tool, not a certified intrusion prevention system. It can misclassify, miss malicious traffic and observe only what its configured logs actually contain. No CVEs, compromises, protection effectiveness or system health may be inferred solely from HTTP status codes or model prose.

## Required deployment safeguards
- Nginx must enforce Basic Auth before proxying NetSec, set `X-NetSec-Authenticated-User $remote_user` and clear `Authorization`. Do not trust a user-supplied header. Python also verifies the source IP of the trusted reverse proxy and same-origin write policy.
- Keep LXC port 8787 private to the trusted proxy; do not router-forward it or allow other LAN clients to impersonate a proxy host.
- HTTPS certificates and Basic Auth credentials are provisioned **locally**, never in this Git archive. Keep `/etc/netsec-proxy-auth.json` pinned to correct proxy and domain.
- Bind-mount Nginx logs **read-only**, with tight ACLs. Do not leak logs or full history into Git.
- Run dashboard/AI as unprivileged `statusdash`; manual bans only via root systemd worker with strict validation. Source AI labels never initiate bans.
- Apply narrow CrowdSec allowlists only for verified testing IPs and review expirations; an allowlist affects all CrowdSec decisions for that origin.
- Current Basic-Auth-only operator model intentionally removes an extra admin token for convenience; it relies on the trusted proxy and TLS/CSRF boundaries. More robust multi-user RBAC/MFA is future work.
- AI logs are untrusted data and should not be permitted to override policies via prompt injection. Verify all major AI claims against immutable deterministic evidence.

## Reporting
Use a private security disclosure channel with the future maintainers. Do not post live IP addresses, credentials, telemetry exports or proof-of-exploit details in public issues.


## v1.1.0 push/analyst data
Authenticated conversation, operator feedback and browser push subscriptions are retained in the private LXC at `/var/lib/server-status/jimmy-workspace.sqlite3`. They are **not** distributed in the public release. The VAPID key and identity stay under root-owned `/etc/netsec-push*`; rotate only with the documented disruptive operation, which clears existing browser subscriptions. Browser push services receive only generic notification text and a report link; delivery necessarily contacts Apple/Google/Mozilla/Microsoft endpoints.

Do not use Jimmy to issue arbitrary shell commands, change bouncer/firewall settings or silently ban hosts. Operator assertions must remain labelled as such and never erase verified telemetry.
