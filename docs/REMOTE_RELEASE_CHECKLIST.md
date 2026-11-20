# Complete release and remote installation checklist

For every subsequent NetSec release:
1. Provide a Git-ready full project ZIP plus SHA-256 and indicate whether it is a standalone release or a targeted patch.
2. Download to Mac `~/Downloads/`; upload using working remote HTTPS temp link if away from LAN (`curl -fsS -T ~/Downloads/<release>.zip https://qurl.sh`, where service is available), or normal `scp` when SSH is reachable. Do not upload private state through public temp link.
3. Open authenticated Proxmox web Shell on host. `curl -fL -o /root/<release>.zip 'VERIFIED_TEMP_LINK'`; verify `sha256sum` against a published checksum.
4. `pct push YOUR_CTID /root/<release>.zip /root/<release>.zip` then `pct exec YOUR_CTID -- python3 -m zipfile -e /root/<release>.zip /root`.
5. Take a Proxmox backup; preserve `/opt/server-status`, `/var/lib/server-status` and `/etc/netsec-*.json` plus Nginx host configurations (separately). Review existing units and config before doing `--upgrade`.
6. Run preflight/tests; install only after matching the actual deployed version. Never assume cumulative text patches will apply cleanly.
7. Verify `server-status.service`, `crowdsec.service`, `netsec-ai.timer`, `netsec-source-ai.timer`, refresh and ban path workers, Nginx Basic Auth session, source labels, last AI assessment and probe records.
8. Record exact backup directory and rollback steps; do not modify host Nginx/bouncer unless documented and specifically intended.
