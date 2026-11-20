# Contributing

MIT-licensed source. Fork into a private repo first, then audit all private deployment data before making it public. Use GitHub issues/PRs for future enhancements.

1. Run `bash ci/check.sh`; include a small regression test with every code change.
2. Never commit `/etc/netsec-ai.env`, passwords, API keys, personal domain strings, host IPs, actual log data, backup archives, report histories, live SQLite databases, GeoIP databases from providers or private CrowdSec decisions.
3. Avoid fragile textual patching. Prefer complete source deployments and schema-compatible migration scripts with backups.
4. Preserve strict Nginx-verified user + pinned proxy address checks, CSRF safeguards and independent CrowdSec ban worker authorization.
5. All model-produced content is **advisory untrusted output**. Never execute AI-written commands or let model labels automatically affect bans.
6. Document any new external network calls, browser permissions or data sent outside the LXC.
7. Use SemVer starting at v1.0.1. `docs/ROADMAP.md` is unimplemented future work, not current release functionality.
