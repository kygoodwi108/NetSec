# Canada + US inbound policy — staged host rollout

**Do not enable country restrictions through a NetSec application upgrade.**
The operator's normal access baseline is Canada + United States for human users, including common US-exit Safari Private Relay traffic. Transmission torrent
peer traffic is worldwide. No AI response may create firewall or CrowdSec bans.

## Scope and boundaries

- HTTPS reverse-proxy sites: Canada + US inbound user access by GeoIP country,
  after validating client IP attribution and the GeoIP2 module.
- Transmission peer traffic: worldwide; do not alter its Proton VPN tunnel,
  routing, kill switch, or torrent listening port.
- Transmission web interface on transmission.kvgoodwin.com: **not** part of
  the worldwide peer exemption. Restrict the administrative UI to Canada and the United States.
- Other direct public listeners (Proxmox 8006, SSH 22, SPICE 3128): Nginx rules
  cannot protect them. Audit router NAT and IPv4/IPv6 reachability separately,
  then stage appropriate host/router firewall controls with an out-of-band
  recovery path.
- Outbound API requests, updates, trackers, and CDN requests: worldwide.
- Unknown GeoIP countries: deny for public administrative sites only after
  controlled verification and a recovery plan.
- Local RFC1918/LAN clients: an explicit local exception may be needed, but
  never trust arbitrary client-controlled X-Forwarded-For headers.

## Preconditions before enforcement

1. Verify actual client address chain (reverse-proxy/CDN) and IPv6 paths.
2. Confirm installed version and module availability:
   `nginx -v; nginx -V 2>&1; dpkg -l libnginx-mod-http-geoip2`.
   Merely finding legacy `geoip_module=dynamic` does **not** establish
   that the GeoIP2 module/database is installed.
3. Install and configure an appropriately licensed, refreshed GeoIP2 country
   database. Test local/Canada/US/unknown country mappings using safe fixtures.
4. Prepare SSH console or other independent recovery access; snapshot Nginx,
   firewall and router settings before modifications.
5. Validate Canada origin, international denial, legitimate travelling-user
   recovery, ACME renewals, monitoring, and Transmission peers before cutover.
6. Run `nginx -t` before every staged Nginx reload. A failing test must leave
   active Nginx unchanged. Do not enable firewall default-deny remotely without
   rollback/watchdog and reliable console access.

The opt-in tested host helper is documented in [HOST_GEOIP_GUARD.md](HOST_GEOIP_GUARD.md). It supports migration from the November 2026 manual CA-only guard, CA+US defaults, independent timed rollback of a country allowlist update, and a separately opt-in monthly host database refresh. The LXC installer never changes these host rules.

## CrowdSec

Keep CrowdSec's behavioural scenarios and bouncer decisions independent of
country access policy. An Nginx GeoIP deny is not necessarily a CrowdSec ban.
Do not automatically create persistent country-wide CrowdSec decisions based on
a model recommendation. Verify real bouncer decision pulls and enforcement
separately, and continue treating foreign traffic as an investigative feature.

## Jimmy user experience

- Markdown headings, paragraphs, lists and inline emphasis must render safely
  in chat bubbles. The renderer must not interpret HTML from logs/model replies.
- Preserve bounded history; distinguish last-24h incident counts from last-15m
  current activity and fresh service checks.
- Canada and the US are expected geographic baselines, **not** proof of benign activity;
  source country, service, traffic direction and authentication outcome govern
  assessment. No unconditional international exemption for the Transmission UI.
- CVE advisory intelligence requires a validated package inventory, including
  distribution backports and relevant module configuration. Never label an
  installed Nginx vulnerable solely from its upstream version string.

## Release gating

The code patch can be merged only after tests, UI rendering review and
non-regression checks. Country enforcement requires independent host-level
staging and explicit live verification. No automatic firewall, Nginx, VPN,
or bouncer modifications are performed by this document or its patch.
