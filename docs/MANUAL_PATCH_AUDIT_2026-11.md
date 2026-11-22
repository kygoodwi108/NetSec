# Manual patch reconciliation audit — NetSec 1.4.3

Reviewed against the manual changes described during the November 2026
Proxmox/NetSec deployment and the consolidated source tree. This is **not**
a disk-level audit of the live host: unreported local edits cannot be inferred
from GitHub or chat logs. Run `nginx -T` / `pct exec 108 -- ...` to compare
actual deployed state before any future cutover.

| Manual change / problem | Repository state after 1.4.3 | Action |
| --- | --- | --- |
| Jimmy historical PatchMon (466) / CrowdSec timer errors, severity | Already committed in v1.4.1 | Retained regression tests in `test_incident_lifecycle.py` |
| Jimmy chat Markdown, message send disabled, clear composer | Already committed in v1.4.1 | Retained; no new API changes |
| iPhone chat textarea squashed by full-width Send | Already committed in v1.4.2 | `mobile.css` and `test_mobile_111.py` |
| Homepage legacy status.json read-only integration | Already in app | Feed was fresh, 10/10 services reporting after fix; no generated host homepage files included |
| GeoIP2 host-country rules and 12 reverse-proxied sites | **Missing** | Added opt-in `scripts/netsec-host-geo-guard.py` to source |
| `libmaxminddb-bin` APT failure on Debian Trixie | Only fixed on live manual script | New packaged host script uses `mmdb-bin` |
| Geo guard leaves stale `backup` after rollback | Only handled by manual `mv` | New guard rotates old backup safely, never deletes |
| Allow Safari iCloud Private Relay US exits | Only operator-modified Nginx | New guard defaults `CA,US` and migrates active legacy policy |
| Automatic GeoIP2 database refresh on Proxmox host | Missing | Added **opt-in host** systemd service/timer; LXC GeoIP timer is separate |
| NetSec v1.4.1 LXC installer hardcoded 1.4.0 | Fixed in GitHub PR #7 | Retained; also fixed repeated backup-name process suffix |
| **Fresh** `proxmox-setup.sh` hardcoded v1.4.0 | **Still broken** | Now validates v1.4.x using `VERSION` |
| NGINX GeoIP policy rollback after confirm / re-enabling | Local script cannot renew policy without manual edits | Packaged `set-countries` command with own five-minute rollback and `confirm` |
| Direct SSH 22 / Proxmox 8006 / SPICE 3128 | No proof they are internet-forwarded | **Not modified**; router and IPv6 reachability audit remains |
| Transmission Proton VPN torrent peer exemptions | Working separate deployment | Unchanged; policy applies to reverse-proxied admin UI only |
| PatchMon sign-in expired message | Operator entered wrong PIN/TFA code | **Not a code defect** |
| Host Nginx reverse-proxy timeouts for long Jimmy operations | Fresh wizard and `examples/nginx-location.conf` already support an extended read timeout | Live host settings must be compared before changing |
| PatchMon proxy WebSocket Upgrade, forwarded headers, buffering disabled, long read timeout | Previously only manual host vhost and prose | Added `examples/nginx-patchmon-location.conf`; not auto-installed |
| Host ACLs allowing unprivileged NetSec to read Nginx logs | Already packaged as `scripts/grant-host-log-acl.sh` | Preserve default ACL for rotated logs; no new host mutation |
| Standalone Homepage 11-item layout / service generator | Separate /var/www/html site, not a NetSec-owned app file | Do not overwrite or publish the host homepage; NetSec's optional read-only feed already supported |
| Nginx hardening and CrowdSec bouncer host state | Existing host config not necessarily in app repo | No automatic importer; no token/certificate/secret exposure |
| NGINX package CVEs / Debian backports | Advisory watchlist in app | Patch status requires separate vendor/distro verification |

The new host guard only touches host Nginx when explicitly invoked. An
ordinary NetSec LXC install/upgrade **does not** install or run it.
Its `set-countries` command supports an active older
`/root/netsec-canada-nginx-guard.py` deployment without overwriting
the legacy `active.json` or its existing `backup`. On migration
it writes a separate `policy-pending.json` and restores the previous
country map if not confirmed within five minutes.

**Boundary:** Canada + US geographic restrictions are an access convenience,
not strong authentication. Private Relay can use countries other than US;
traveling users can still be blocked. Unknown locations remain denied;
country is not an identity or authorization signal. Always keep HTTP
authentication and CrowdSec protections.

## Follow-up — v1.4.3 service-status hotfix

The legacy Homepage feed is an operator-owned read-only `status.json`. A momentary
missing/partially written/invalid JSON feed previously made all services disappear
from NetSec despite a working mount; if no direct checks were configured the UI
incorrectly reported "No services configured." The hotfix caches the latest fresh
valid sample **in memory for at most one hour**, explicitly renders it as
**STALE — not live**, preserves the source as `homepage` on unavailable data,
and prioritizes configured direct checks when the Homepage feed is stale.
No saved file, database, or Homepage generator is overwritten.
A full process restart clears this optional last-known cache.

The **cause of any particular live 0/10 incident remains unverified** without
fresh logs from the host. This patch makes the monitoring status honest and
resistant to short JSON-write interruptions; it does not repair an unhealthy
external Homepage status generator.
