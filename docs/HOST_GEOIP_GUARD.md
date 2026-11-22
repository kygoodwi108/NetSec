# Proxmox host GeoIP2 guard — Canada + United States

**Opt-in HOST tool.** NetSec's LXC 108 installer does not install country
blocking and never changes host Nginx, router forwarding or firewall rules.
The script is `scripts/netsec-host-geo-guard.py`; it is safe to keep a
copy in `/usr/local/sbin/` on the **Proxmox host**. Requires root and
checks `/etc/pve` to avoid accidentally running in a container.

## Existing installation / November 2026 guard migration

Your original manual guard already deployed:
- `/etc/nginx/conf.d/90-netsec-canada-geo.conf`
- `/root/netsec-canada-nginx/active.json`
- 12 server-block deny checks containing `NETSEC_CANADA_HTTPS_GATE`

**Do not run `enable` again.** The new guard detects and preserves this
deployment, plus the existing original Nginx backups and rollback script.
It can update the existing country map without re-inserting any server block:

```bash
# From root@pve; first copy the verified release script to the host:
install -m 0755 scripts/netsec-host-geo-guard.py /usr/local/sbin/netsec-host-geo-guard.py

python3 /usr/local/sbin/netsec-host-geo-guard.py status
python3 /usr/local/sbin/netsec-host-geo-guard.py set-countries --countries CA,US
# A real Canadian device AND a real US-origin connection must work,
# and a known third-country source should receive 403.
python3 /usr/local/sbin/netsec-host-geo-guard.py confirm
```

If the existing map already permits CA+US, set-countries reports
"already allows" and changes nothing. For an unfamiliar or edited map
it stops instead of guessing. A pending change has its **own**
five-minute systemd rollback, and `rollback-policy` restores the
previous country map without discarding the 12 HTTPS server rules.

```bash
python3 /usr/local/sbin/netsec-host-geo-guard.py rollback-policy
```

**Full disable**, only if intended:

```bash
python3 /usr/local/sbin/netsec-host-geo-guard.py rollback
```

This restores the original site files from the legacy deployment's
manifest and removes country filtering entirely.

## Fresh Proxmox host

On a new host with Nginx reverse proxy, first ensure a separate LAN
console and reliable recovery path. Dry-run package changes before
running prepare. Do not run these commands from the NetSec LXC:

```bash
apt-get install --simulate libnginx-mod-http-geoip2 mmdb-bin
python3 /usr/local/sbin/netsec-host-geo-guard.py prepare
python3 /usr/local/sbin/netsec-host-geo-guard.py enable --countries CA,US
# Test Canadian and US clients; test third-country denial.
python3 /usr/local/sbin/netsec-host-geo-guard.py confirm
```

`prepare` downloads the current monthly DB-IP Country Lite MMDB over
HTTPS (CC BY 4.0) and tests selected country lookups before atomic
replacement. `enable` saves HTTPS configuration files under
`/root/netsec-canada-nginx/backup`, preserves older backup directories,
adds only missing HTTPS server checks, validates Nginx and starts an
automatic five-minute rollback. No secret keys are exported.

## Optional monthly host GeoIP database refresh

A country database is **not** maintained by the LXC's
`netsec-geoip-update.timer`, which updates the dashboard database.
For the host database, explicitly install the two host units:

```bash
install -m 0644 host-systemd/netsec-host-geoip-update.service /etc/systemd/system/
install -m 0644 host-systemd/netsec-host-geoip-update.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now netsec-host-geoip-update.timer
systemctl list-timers netsec-host-geoip-update.timer
```

The timer calls `refresh-db` monthly. An unsuccessful download leaves
the old valid DB intact. The current Nginx GeoIP2 module's
`auto_reload 60m` handles DB refresh without resetting rules.
If the DB format/provider changes, disable this timer and review the
script rather than bypass validation.

## Coverage limits

- Nginx HTTPS site restrictions apply to the remote TCP address, not
  client-supplied `X-Forwarded-For`. Local RFC1918, IPv6 ULA/link-local
  and loopback peers are allowed.
- Torrent peers worldwide through Proton VPN remain unrestricted, but
  the Transmission **web administration** vhost is filtered.
- Plain HTTP/port 80 remains unfiltered to avoid breaking ACME/redirects.
  Review each public non-redirect route.
- Proxmox 8006, SSH 22, SPICE 3128, forwarded LXC ports, router NAT
  and separate IPv6 entry points are **not protected by Nginx rules**.
  A local listening port does not mean a public port forward exists.
- Safari Private Relay may exit elsewhere than the US. Real access tests
  still matter. Country allowlists do not replace service authentication.
- Guard reloads with `nginx -t` are not a substitute for controlled
  CA/US/third-country access verification. Retain a separate console.
