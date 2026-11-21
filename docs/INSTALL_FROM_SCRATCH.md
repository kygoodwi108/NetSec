# NetSec 1.4.0 — Complete fresh Proxmox installation guide

**Status:** development branch; release only after CI and host smoke testing. This package has automated tests and a local HTTP smoke test; **a full Debian 12 Proxmox + CrowdSec host-bouncer + phone push delivery test is still required**. Do not remove a working installation until the replacement and the rollback have been demonstrated. `scripts/proxmox-setup.sh` runs **on the Proxmox host**, creates **a new LXC**, and refuses existing IDs and Nginx virtual-host names. It does not support an in-place reinstall.

## 1. Architecture and prerequisites

```
Internet / optional Cloudflare
     │
     ▼
Proxmox host Nginx :443  ─── CrowdSec Nginx bouncer (host-wide; OPTIONAL)
     │                          │
     │                          └─ private relay (new NetSec LXC :8081) ── LAPI :8080
     └─ HTTPS Basic Auth ── new NetSec Debian 12 LXC :8787
                                    ├─ read-only bind mount of host Nginx logs
                                    ├─ built-in HTTP/TCP checks of any host/VM/LXC
                                    ├─ offline GeoIP + Jimmy scheduled analyst
                                    ├─ authenticated assessment-specific chat/feedback
                                    └─ optional Web Push worker (external browser push services)
```

Required: Proxmox VE host shell as root; an unused LXC ID and static private LAN IPv4/CIDR outside the DHCP allocation; correct gateway, DNS and bridge; active template and root-disk storage; host Nginx, `nginx -t`, `certbot`, `apache2-utils`, `acl`, Python 3; Internet during installation. The LXC defaults to Debian 12, 2 CPU, 2 GiB RAM, 16 GiB disk. Provide more resources if the workload requires it.

Run on **Proxmox host** before starting:

```bash
apt-get update
apt-get install -y git curl unzip nginx certbot apache2-utils acl
nginx -t
pvesm status
pveam available --section system | grep debian-12-standard
```

For HTTPS, your **new** FQDN must reach the host's TCP/80 and TCP/443, and the Let's Encrypt challenge must work (temporarily set a Cloudflare hostname DNS-only if required; afterwards use Full/Strict TLS). The wizard can reuse a certificate already on the host, but will never replace a conflicting Nginx site. Do not expose NetSec's LXC `:8787` or CrowdSec LAPI `:8080/:8081` directly to the Internet.

A ChatGPT subscription is **not** OpenAI API credit. Choose either (a) OpenAI and **your** valid API key and model such as `gpt-4.1-mini`, or (b) a reachable Open WebUI instance, its private API key, and the **actual model ID** such as your local `jimmy` model. An assistant *display name* is not the model ID.

## 2. Back up before replacing an existing NetSec

**Skip this section only for a first installation with no prior NetSec.** Keep a live installation (e.g. LXC 108) running while you test a second LXC (e.g. 150).

On host, make a private directory and capture machine-readable configs:

```bash
BACKUP="/root/netsec-before-1.4.0-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$BACKUP"
pct config 108 > "$BACKUP/ct108.config.txt"    # adjust for your live CTID
cp -a /etc/nginx "$BACKUP/nginx"
cp -a /etc/letsencrypt "$BACKUP/letsencrypt"
if [ -d /etc/crowdsec/bouncers ]; then cp -a /etc/crowdsec/bouncers "$BACKUP/bouncers"; fi
chmod 700 "$BACKUP"
# Verify a Proxmox backup storage has sufficient space and backup content enabled.
vzdump 108 --mode snapshot --storage local --compress zstd
# Record the exact backup filename and make sure it can be listed/read.
ls -lh /var/lib/vz/dump/vzdump-lxc-108-*.tar.zst | tail -3
```

The backup contains secrets and private IP data. **Never upload it to GitHub, qurl.sh, or public file-transfer services.** Host Nginx, TLS keys and CrowdSec bouncer config are outside the LXC and require the separate copies above. A second separate/private off-host copy is prudent before destructive replacement. `vzdump` support and backup location depend on Proxmox storage; do not proceed on a failed backup.

## 3. Get the complete release on Proxmox (local or remote)

The recommended artifact is the **full source ZIP**, not a legacy cumulative patch. Download `netsec-v1.4.0-source.zip` from the release attached to this conversation or a verified official release after publication.

**Mac on the same LAN / SSH available:** in macOS Terminal:

```bash
scp ~/Downloads/netsec-v1.4.0-source.zip root@192.168.1.10:/root/
```

Replace the IP for other installations. If your Mac is **away from home** and cannot SSH to the private host, keep using your existing temporary HTTPS link workflow. On Mac:

```bash
curl -fsS -T ~/Downloads/netsec-v1.4.0-source.zip https://qurl.sh
```

Copy the **actual returned private temporary HTTPS download URL** (never invent it). In the Proxmox web Shell:

```bash
curl -fL --retry 3 -o /root/netsec-v1.4.0-source.zip 'PASTE_RETURNED_TEMPORARY_URL'
sha256sum /root/netsec-v1.4.0-source.zip
```

Compare the displayed SHA-256 with the separately published **verified release hash**. Abandon the file on mismatch; never guess a hash. This transfer is only for **public source code**, not private backups or keys. Delete the temporary uploaded copy after verification as supported by the transfer service.

**Extract + test on Proxmox host:**

```bash
mkdir -p /root/netsec-1.4.0
unzip -q /root/netsec-v1.4.0-source.zip -d /root/netsec-1.4.0
cd /root/netsec-1.4.0/netsec-v1.4.0
cat VERSION                        # expect 1.4.0
bash ci/check.sh                    # offline tests before creating a container
bash -n scripts/proxmox-setup.sh
bash scripts/proxmox-setup.sh --help
```

If you instead run the wizard from a Git checkout, **first verify the checkout's `VERSION` says `1.4.0`** and that its source matches the reviewed release. Don't run an old `main` branch and assume it includes 1.4.0.

## 4. The interactive wizard: what every question means

On **Proxmox host**, from the extracted source:

```bash
cd /root/netsec-1.4.0/netsec-v1.4.0
bash scripts/proxmox-setup.sh
```

Typical **staging example** (adapt to your network; never copy a live IP used by another CT):

| Prompt | Example | Meaning |
|---|---|---|
| New unused LXC ID | `150` | Must not exist. Never enter `108` if production still exists |
| Container hostname | `netsec-test` | Local Linux hostname; not an FQDN |
| Static private IP/CIDR | `192.168.1.50/24` | Reserve it on your LAN |
| Gateway | `192.168.1.1` | Actual LAN router |
| DNS | `1.4.0.1` | Use a resolver reachable by the LXC; setup checks DNS as `_apt` |
| Network bridge | `vmbr0` | Proxmox bridge |
| Template storage / disk storage | `local` / `local-lvm` | Must be active |
| Disk | `16` | GiB |
| Assistant name | `Jimmy` | On-screen name, **not the AI model** |
| AI provider | `1` OpenAI, `2` local Open WebUI, `3` none | Choose **2** for a local model named `jimmy` |
| Model ID | e.g. `gpt-4.1-mini` or `jimmy` | Must match the selected provider |
| API key | hidden | Never upload or paste into issue/chat/GitHub |
| HTTPS hostname | `netsec-test.example.com` | Must be publicly DNS-resolvable; separate from existing production site |
| HTTPS email/login/password | Your own | Password ≥12 chars; Nginx Basic Auth serves the app |
| Read host Nginx logs | Yes | Read-only host mount with mapped UID ACL |
| CrowdSec engine | Yes for detection | A standalone engine inside the new LXC |
| Bouncer | Keep / New / Cutover | **Host-wide**, see §5 |
| AI automation | Optional | Sends requests repeatedly; enable only after one-shot test |
| Web Push | Optional | Requires HTTPS, external push service and device opt-in |

### The service-monitoring question — **this is where you add services**

You will see `=== INFRASTRUCTURE MONITORING ===` and:

```text
Configure your servers/websites now? [Y/n]:
Add service name (e.g. Proxmox VE, Nginx, Plex; blank only when finished): Proxmox VE
Type: 1=HTTP(S), 2=TCP [1]: 2
Host IPv4/DNS (without port): 192.168.1.10
TCP port (1-65535) [8006]: 8006

Add service name (e.g. Proxmox VE, Nginx, Plex; blank only when finished): Nginx
Type: 1=HTTP(S), 2=TCP [1]: 2
Host IPv4/DNS (without port): 192.168.1.10
TCP port (1-65535) [8006]: 443

Add service name (e.g. Proxmox VE, Nginx, Plex; blank only when finished):
```

**The final blank name ends the list, not the entire server installation.** The wizard prints the named endpoints before creation. If you selected monitoring but added zero services, it prints a warning and makes you explicitly confirm continuing without them. `Y`/Enter on the first prompt means yes; don't leave subsequent service names blank if you want them monitored. HTTPS endpoints with self-signed certificates are better represented by TCP checks, which indicate reachability only. Checks do **not** verify Proxmox VM power states or the internals of an application.

For another person's server, enter their real IPs or hostnames, ports, or HTTP(S) health URLs. **Nothing here is tied to the author's homepage.** Advanced users can edit `services` in `/opt/server-status/config.json` after install, then restart `server-status.service`.

## 5. CrowdSec Nginx bouncer: three choices (important)

The CrowdSec **engine** detects; the **bouncer** enforces. The engine is independent inside the LXC; the bouncer runs where Nginx runs (the Proxmox host in this example).

1. **Keep current host bouncer unchanged** — default, safe for testing. CrowdSec in the LXC observes logs, while the host's existing bouncer remains connected to its current LAPI. No newly detected decisions on the new engine are enforced by the old bouncer.
2. **New host Nginx bouncer** — use only if the host does not already have a configured bouncer. The wizard checks the package, config and relay before changing files.
3. **Cut over existing host bouncer** — changes the LAPI used for **every Nginx site** on this host. Requires explicit typed `SWITCH-TO-<CTID>` confirmation, backups, and `nginx -t`. Only after a known-good backup and a deliberate cutover window. If the existing config has an unrecognized `.conf.local` override, the helper refuses auto-change and requires manual reconciliation.

On a host with existing production Nginx/CrowdSec, **do not choose New** to bypass a working bouncer. Do not erase the old CrowdSec engine until a controlled test demonstrates the new bouncer is connected and blocks a chosen safe test IP. The installer leaves manual dashboard ban execution disabled until verified separately. Registered bouncer ≠ recent LAPI pull ≠ confirmed blocking.

To check on Proxmox after the bouncer is configured:

```bash
pct exec 150 -- cscli lapi status
pct exec 150 -- cscli bouncers list
pct exec 150 -- systemctl is-active netsec-lapi-relay.service
nginx -t
```

For a controlled test, add a **temporary, non-trusted test IP** to the new CrowdSec LAPI, use an outside test client at that IP, expect an actual Nginx denial, then remove the decision. **Never test-ban your own admin IP, Cloudflare shared proxy IP, or the Proxmox host.** Exact synthetic enforcement depends on your reverse-proxy/logging/real-client-IP setup. When Cloudflare is used, configure trusted proxy headers properly or the bouncer may see the wrong source IP. Backup location used by the cutover helper is printed as `/root/netsec-bouncer-backups/...-ct<CTID>` on the Proxmox host.

## 6. GeoIP, Jimmy chat, PWA and Web Push

- GeoIP is downloaded by the installer as the non-root `statusdash` user and refreshed monthly. A network failure prints `WARNING`; it never silently marks the map active.
- Jimmy detailed assessment lives on **Jimmy Analyst** tab. The Command Hub retains heuristic risk and a concise Jimmy summary.
- `Ask Jimmy` requires an authenticated HTTPS operator session. Each chat is tied to a saved assessment ID/time, with local history. It uses **your configured AI provider** and includes bounded read-only checks of configured HTTP/TCP services and local enforcement export; it does not execute model-proposed commands, run arbitrary shell commands, or create bans.
- Operator feedback: **I confirm**, **That is expected**, **I own this IP**, **I disagree**, **Maintenance until...**. Records include author, UTC timestamp and expiry. Only the explicit IP-ownership action writes a friendly *dashboard metadata label*, not CrowdSec enforcement. Feedback enters subsequent AI prompts as **unverified operator context**; deterministic risk evidence remains authoritative and reports show a before/after severity comparison.
- PWA: on Android use **Install App/Add to Home screen** in your browser. On iPhone use **Safari → Share → Add to Home Screen**, then open the installed app. On supported iOS (16.4+), push permission is only offered after Home Screen installation and a direct click. All devices need HTTPS, a successful Nginx Basic Auth login and explicit notification permission.
- Web Push is optional. Setup installs `pywebpush==2.5.0` into `/opt/netsec-push-venv`, creates private VAPID key material under `/etc/netsec-push*`, and enables `netsec-push.timer`. These files **must never** go into GitHub or a public source release. Browser push providers are external, so subscription delivery uses their services; no log content/IP details appear in a notification. Users subscribe from Jimmy's tab and can send a self-test.
- Notifications are deduplicated for a continuing evidence-calibrated red incident, with a six-hour repeat suppression for the same reason category. Operator-controlled quiet periods (0-72h), acknowledgements and an optional single delayed reminder (1/3/8h) are available. These are **advisory**, never autonomous CrowdSec actions.
- Rotating VAPID keys is a **manual**, disruptive administrator action: `pct exec 150 -- bash /root/netsec-setup/scripts/rotate-push-vapid-lxc.sh ROTATE-VAPID`. Existing device subscriptions are invalidated and users must opt in again; private old-key backups stay on the LXC host root directory.

## 7. Verify the entire deployment before using it

On Proxmox:

```bash
CTID=150
pct status "$CTID"
pct exec "$CTID" -- systemctl is-active server-status.service
pct exec "$CTID" -- bash /root/netsec-setup/scripts/verify.sh
pct exec "$CTID" -- stat -c '%a %n' /etc
pct exec "$CTID" -- runuser -u _apt -- getent ahostsv4 deb.debian.org
pct exec "$CTID" -- python3 -c 'import json;d=json.load(open("/opt/server-status/config.json"));print(json.dumps(d.get("services",[]),indent=2))'
pct exec "$CTID" -- curl -sS -o /dev/null -w 'API %{http_code}\n' http://127.0.0.1:8787/api/status
pct exec "$CTID" -- curl -sS -o /dev/null -w 'PWA %{http_code}\n' http://127.0.0.1:8787/manifest.webmanifest
pct exec "$CTID" -- curl -sS -o /dev/null -w 'Push worker page %{http_code}\n' http://127.0.0.1:8787/sw.js
pct exec "$CTID" -- curl -sS -o /dev/null -w 'Privileged API %{http_code}\n' http://127.0.0.1:8787/api/jimmy/workspace
```

Expected: dashboard/PWA/service-worker `200` and **direct privileged workspace `403`**. A direct unauthenticated privileged API returning `200` is a **critical failure: stop before exposure**. `/etc` must be `755` and `_apt` should resolve Debian's hostname.

```bash
pct exec "$CTID" -- ls -lh /var/lib/server-status/geoip-country.sqlite3
pct exec "$CTID" -- systemctl list-timers --all | grep netsec
pct exec "$CTID" -- systemctl start netsec-ai.service   # one real call, may be billable
pct exec "$CTID" -- systemctl show netsec-ai.service -p Result -p ExecMainStatus
pct exec "$CTID" -- journalctl -u netsec-ai.service -n 25 --no-pager
nginx -t
curl -I https://netsec-test.example.com/                  # without login should be 401
```

The AI `oneshot` service normally ends inactive after success; `Result=success` and `ExecMainStatus=0` are key. Test a real Ask Jimmy message and feedback submission while logged in. Refresh the AI analysis and verify the new report references operator feedback separately from evidence. Verify manually selected service checks appear in the UI and that GeoIP has country rows from public client IP traffic.

If opted into Web Push:

```bash
pct exec "$CTID" -- systemctl is-active netsec-push.timer
pct exec "$CTID" -- systemctl start netsec-push.service
pct exec "$CTID" -- journalctl -u netsec-push.service -n 25 --no-pager
```

On a supported real phone: install PWA, sign in, enable notifications, run self-test, receive notification, tap to open Jimmy (authenticate if needed), and acknowledge a test incident. Fake simulated red status in a unit test is **not** equivalent to verified Nginx/CrowdSec red detection or live push provider delivery.

## 8. Complete staging → production cutover and rollback planning

If the old installation is still active, keep it until **all** of the above checks have passed. Take a second backup before any host-wide bouncer cutover, and record its printed backup directory. Do not remove the current production Nginx site until its configuration, Basic Auth file and TLS keys are privately backed up. Fresh wizard refuses an existing domain—use a separate staging domain, then plan the intentional DNS/Nginx cutover.

A safe rollback from a failed bouncer cutover involves restoring the saved host bouncer config, `nginx -t && systemctl reload nginx`, and keeping or restarting the former CrowdSec LAPI. For failed app deployments, restore the existing LXC or `vzdump` archive only after verifying the exact CTID and backup path. A replacement same-ID restore requires stopping/destroying the failed replacement first; **do not run it on your old active 108**. Ensure host Nginx upstream IP and certificate still point to the intended container. Never assume restoring a NetSec LXC automatically restores host Nginx, TLS or CrowdSec bouncer state.

## 9. Manual file transfer/install inside an already-created **test** LXC

This is **not** a substitute for the complete host wizard when testing auto-provisioning, but it is useful for a reviewed upgrade or recovery. On Proxmox, with a trusted, unpacked release and a **non-production** target LXC:

```bash
CTID=150
pct push "$CTID" /root/netsec-v1.4.0-source.zip /root/netsec-v1.4.0-source.zip
pct exec "$CTID" -- python3 -m zipfile -e /root/netsec-v1.4.0-source.zip /root/netsec-release
pct exec "$CTID" -- bash /root/netsec-release/netsec-v1.4.0/scripts/install-lxc.sh --fresh
```

This manual path does **not** automatically set up host Nginx/HTTPS, CrowdSec, GeoIP, AI credentials or Web Push. For complete fresh provisioning, always use `scripts/proxmox-setup.sh` from the **Proxmox host** instead. Do not run `--fresh` over an existing app; reviewed upgrades use `--upgrade` with a verified backup and compatibility checks.


## Automatic updates introduced in v1.2

After the initial installation (or the first manual v1.2 upgrade), NetSec enables the `netsec-auto-update.timer` systemd timer inside its LXC. Every day, with random delay, it checks the *latest stable* GitHub Release from `kygoodwi108/NetSec` and upgrades only when the release includes a correctly named source ZIP and SHA-256 digest. GitHub release assets are the update channel; pushing to main alone does not automatically deploy new code.

The updater backs up application code and service units before updating, checks the release source and Python tests before installation, verifies the running service, and restores the previous application version on upgrade failure. Persistent databases are preserved and **cannot be automatically downgraded if a future version makes irreversible schema changes**; releases must ship backwards-compatible database migrations. Maintain separate host or Proxmox LXC backups for disaster recovery.

Inspect or disable the updater inside the LXC:

```bash
systemctl list-timers netsec-auto-update.timer
journalctl -u netsec-auto-update.service -n 100 --no-pager
systemctl disable --now netsec-auto-update.timer
```

To bootstrap an existing NetSec v1.1 LXC, manually download the published v1.4.0 source archive to your computer, transfer to Proxmox (or through your existing temporary HTTPS file-link workflow when remote), then on `root@pve`:

```bash
# Adjust filename only if your actual downloaded release asset differs.
sha256sum /root/netsec-v1.4.0-source.zip
pct push 108 /root/netsec-v1.4.0-source.zip /root/netsec-v1.4.0-source.zip
pct exec 108 -- python3 -m zipfile -e /root/netsec-v1.4.0-source.zip /root/netsec-upgrade-120
# Confirm extracted root path; for standard package use:
pct exec 108 -- bash /root/netsec-upgrade-120/netsec-v1.4.0/scripts/install-lxc.sh --upgrade
pct exec 108 -- systemctl is-active server-status.service
pct exec 108 -- systemctl list-timers netsec-auto-update.timer
```

**Verify the ZIP hash against the published release SHA-256 before installing.** The extracted top-level directory may differ depending on packaging; check before running the last installer command. Never run the *fresh Proxmox setup wizard* against an existing LXC such as 108. For third-party installs, replace 108 with the actual existing container ID; don't assume host Nginx, HTTPS, CrowdSec or the GPU should be changed by the app updater.


### Existing reverse proxy: longer Jimmy chat timeout

Jimmy v1.2's larger context can take more than the 60-second proxy timeout used in v1.1 installers. On existing systems, inspect the **specific NetSec HTTPS Nginx server block on the Proxmox host** and change the NetSec upstream location's `proxy_read_timeout` to `420s`; use `nginx -t && systemctl reload nginx`. Do not change unrelated sites, and do not overwrite the entire HTTPS server block. The v1.2 **fresh** wizard sets the longer timeout automatically. The application updater does not edit host Nginx.


### Unified source investigations in v1.3

Open **Source Intelligence** and select an IP. The request explorer shows sanitized Nginx access entries across available logs, with pagination, status/path filters, and coverage warnings for missing or truncated history. HTTP 2xx is not evidence of successful exploitation. Query strings, headers, cookies and bodies are never returned. Inline classifications persist via the existing authenticated operator endpoint; bans are queued through CrowdSec and are not represented as verified enforcement until the worker/bouncer confirms them.

For an existing LXC such as 108: verify the release ZIP against published SHA256SUMS.txt, take a vzdump backup, transfer the ZIP to Proxmox, run `pct push 108 /root/netsec-v1.4.0-source.zip /root/netsec-v1.4.0-source.zip`, extract with `pct exec 108 -- python3 -m zipfile -e /root/netsec-v1.4.0-source.zip /root/netsec-upgrade-130`, and then `pct exec 108 -- bash /root/netsec-upgrade-130/netsec-v1.4.0/scripts/install-lxc.sh --upgrade`. Verify the dashboard and the existing auto-update timer afterwards.

## PatchMon optional companion

Deploy PatchMon in a **separate dedicated Debian VM**, not the NetSec LXC or Proxmox host. Follow [PatchMon fresh installation and read-only integration](PATCHMON.md). Jimmy shows PatchMon's HTTP reachability only, without patch-execution authority.
