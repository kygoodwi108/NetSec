# Publish NetSec 1.1.0 to GitHub — safe staging branch workflow

Use the **complete verified source ZIP**, not a partial patch series. These steps run on a workstation or the Proxmox host with Git credentials; they do not touch running LXCs. `VERSION` must say `1.1.0`. Never push `/etc/netsec-*`, `/var/lib/server-status`, certificate files, personal Nginx logs, or push keys.

```bash
# In an existing, authenticated checkout of https://github.com/kygoodwi108/NetSec
cd /root/netsec-test-source
# Review/commit/stash local changes first, rather than overwriting them blindly.
git status --short
git fetch origin
git switch -c release/netsec-1.1.0 origin/main
# Extract the full ZIP beside the repo:
mkdir -p /root/netsec-1.1.0-release
unzip -q /root/netsec-v1.1.0-source.zip -d /root/netsec-1.1.0-release
# Copy release source into the repository, but NEVER overwrite .git:
rsync -a --exclude=.git --exclude=__pycache__ \
  /root/netsec-1.1.0-release/netsec-v1.1.0/ ./
cat VERSION
bash ci/check.sh
git diff --check
git status --short
git add -A
git diff --cached --stat
# REVIEW staged files for real credentials, private IP logs and secrets before commit:
git diff --cached --check
git commit -m 'NetSec 1.1.0: Jimmy analyst workspace, operator feedback, PWA and push'
git push -u origin release/netsec-1.1.0
```

Open a pull request from `release/netsec-1.1.0` to `main`. Validate it on a **fresh staging** LXC, including bouncer and phone push opt-in, before merge/tag. Do not force-push a published `main` or automatically overwrite a working host bouncer. Once reviewed, merge and tag the immutable `v1.1.0` from the tested commit.
