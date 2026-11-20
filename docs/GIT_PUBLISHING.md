# Prepare for Git hosting

This ZIP is laid out as a repository root. Extract it, review licenses/config examples and scan for private secrets, then initialize a local repository:

```bash
cd netsec-v1.0.1
bash ci/check.sh
git init
git add .
git status --short
git commit -m 'NetSec v1.0.1 consolidated source baseline'
git tag v1.0.1
```

**Do not push automatically.** Review `git diff --cached` and scan for API tokens, model keys, private IPs, certificates, real hostnames, actual security logs and private notes. These files intentionally were not included in this source ZIP. Create a public remote only after a deliberate security review and preferably independent testing on a clean LXC. If committing public build output, include only `docs`/source, not `backup-state.sh` output or any files under `/var/lib/server-status`.
