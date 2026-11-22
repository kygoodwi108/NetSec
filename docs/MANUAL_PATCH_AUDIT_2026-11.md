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
