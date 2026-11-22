# NetSec security intelligence stage 2 (read-only)

## Capabilities

- A dated NGINX advisory **watchlist** sourced from
  https://nginx.org/en/security_advisories.html (reviewed 2026-11-21).
  This is not a continuously updated CVE database. Do not assume a listed CVE
  applies without a verified package revision and feature configuration.
- Read-only operator-supplied inventory in
  `/etc/netsec-software-inventory.json` (max 16 KB). No remote host probing.
- Canada-first **monitoring** for Nginx inbound HTTP request geography.
  GeoIP alone is not identity, authentication outcome, or evidence of attack.
  Transmission torrent peer traffic is a worldwide exception; Transmission's
  administrative web UI is still Canada-only when host enforcement is enabled.
- CrowdSec LAPI last valid bouncer pull age, separately from actual enforcement.
  A recent pull alone never proves a controlled HTTP denial.
- Dynamic Jimmy findings with `active`, `recovered`, and `unverified`
  lifecycle labels. Historical counts are preserved.
- All feedback is advisory. No automated bans, firewall edits or Nginx changes.

## Optional inventory for CVE applicability

Populate this file on LXC 108 only after verifying the HOST Nginx package
version and features (not the NetSec container's nginx, if any).

Host read-only checks:

```bash
nginx -V 2>&1
dpkg-query -W nginx nginx-common 2>/dev/null
apt-cache policy nginx
nginx -T 2>&1 | grep -Ei 'http2|quic|resolver|mail'
```

An example *operator assertion* inventory:

```json
{
  "schema_version": 1,
  "components": [
    {
      "name": "nginx",
      "version": "REPLACE_WITH_HOST_UPSTREAM_VERSION",
      "package_revision": "REPLACE_WITH_EXACT_HOST_PACKAGE_REVISION",
      "vendor_patch_status": "unknown",
      "features": {
        "http2": null,
        "http3": null,
        "resolver": null,
        "mail": false
      }
    }
  ]
}
```

The values `unknown`, `confirmed_patched`, and `needs_vendor_review`
are operator attestations, NOT verified telemetry. Only fill true/false
features when checked. Beware Debian backported security fixes. Installing
the application patch does not update Nginx itself.

Read-only conditions for raised concern:
- A registered CrowdSec bouncer without a fresh parseable LAPI pull may cause
  Amber; investigate exporter freshness and real enforcement.
- Foreign HTTP request counts are informational, never a basis for automatic
  country bans or a compromise claim.
- CVE matches without verified package applicability produce review findings,
  NOT automatically confirmed compromise.

## Canada-only host enforcement

See `docs/CANADA_FIRST_POLICY.md`. This patch DOES NOT deploy any country
restriction. Host firewall and Nginx GeoIP2 changes need separate testing and
console recovery. Nginx restrictions do not cover direct SSH, Proxmox:8006
or SPICE:3128 listeners, nor every IPv6 ingress route.

A further concern: geographic restrictions should account for legitimate
non-Canadian uptime monitors and certificate authority HTTP validation.
Preserve outbound software updates, API access and Proton VPN traffic.

## Acceptance criteria

- Replay the PatchMon 466-error historical outage and current live failures.
- Check a CrowdSec pull newer than five minutes versus stale and malformed
  bouncer timestamps.
- Distinguish a single foreign scan from confirmed login success.
- Match NGINX CVE advisories only to confirmed relevant feature configuration;
  never infer vulnerability solely from `nginx -v`.
- Confirm UI Markdown and history still work on phones and desktop.
- Run `bash ci/check.sh` and `bash ci/check-ui.sh` before any installation.
- No enforcement change without independent console access and a revert plan.
