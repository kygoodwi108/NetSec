# Architecture v1.0.1

```text
Internet -> authenticated HTTPS Nginx (on Proxmox) -> dashboard LXC :8787
               |                                 | Python app + Intel Hub
               | Nginx access/error logs         | admin actions verified by Nginx identity + proxy source
               |                                 | Jimmy assessment/source AI -> Open WebUI -> local model
               +-> CrowdSec Nginx bouncer <----- LAPI relay <----- CrowdSec engine (LXC)
               |                                 |
               +-> read-only mounted logs ------ +-> bounded local log readers
                                                 |-> exported cscli metadata JSON
Manual ban: verified browser -> bounded JSON queue -> root systemd worker -> cscli
AI source classification: logs -> Open WebUI -> advisory SQLite label; no ban edge
```

## Security trust boundaries
- Nginx terminates public TLS and authenticates. Set user header **after** successful Basic Auth. Python **also** requires a matching pinned proxy source IP and valid origin/actions for writes. Nginx must overwrite client-supplied authentication headers.
- No assumption of VPN-only access. Keep secure direct remote HTTPS access while requiring strong auth.
- Root-only workers run fixed, validated actions; Jimmy cannot submit shell commands.
- CrowdSec detection and decision-making are separate from Nginx enforcement; observing a registered bouncer is not proof of recent enforcement unless log/controlled HTTP evidence supports it.
- The source dataset is Nginx access/error logs and exported decisions, not raw network packets, arbitrary SSH sessions, BitTorrent peers or endpoint EDR.
- Secrets, operator labels, assessments and source history are runtime state, not Git source.

## Runtime paths
- Code: `/opt/server-status/`
- Source Intelligence: `/var/lib/server-status/intel/` including `ip-metadata.json`, history and AI labels
- Jimmy assessments and probes: `/var/lib/server-status/ai/`
- Ban requests/results: `/var/lib/server-status/ban-queue/`
- Core configuration: `/opt/server-status/config.json`
- Proxy login policy: `/etc/netsec-proxy-auth.json`
- Diagnostics: `/etc/netsec-diagnostics.json`
- Local model/API settings: `/etc/netsec-ai.env`
- Host Nginx log bind mount: `/mnt/nginx-logs`

## Primary services
`server-status.service`, `netsec-ai.service/.timer`, `netsec-source-ai.service/.timer`, `netsec-ai-manual.path`, `netsec-ban-worker.path`, `netsec-alert-export.timer`, `netsec-enforcement-export.timer`, `crowdsec.service` (installed separately).
