# Publish NetSec 1.1.1 to GitHub with Finder (no Mac Terminal)

This release upgrades `1.1.0`. Download and extract `netsec-1.1.1-github-drag-drop.zip` from the verified release attachment. **It contains only added/modified public source files**, in the repository's folder structure. Never upload private `config.json`, certificates, log archives, push VAPID keys, credentials or any `/var/lib/server-status` file.

1. Open Finder → Downloads; double-click the ZIP. Open the extracted **NetSec-1.1.1-GitHub-Upload** folder.
2. Open `https://github.com/kygoodwi108/NetSec` in a browser; select the `main` branch; choose **Add file → Upload files**.
3. Select all the contents **inside** the extracted folder, and drag them into GitHub's upload area. Do **not** drag the outer folder itself or the ZIP. The displayed paths should start with `app/`, `docs/`, `scripts/`, `tests/`, `systemd/`, or root filenames such as `VERSION`.
4. Confirm you see `app/mobile.css`, `app/mobile-ui.js`, `app/index.html`, `app/app.py`, `VERSION`, `scripts/install-lxc.sh`, `SOURCE_SHA256SUMS.txt`, `docs/MOBILE.md` and `tests/test_mobile_111.py` among the changes. The `VERSION` must be `1.1.1`.
5. Commit message: `NetSec 1.1.1 - phone dashboard, bottom navigation and mobile log cards`. Commit directly to `main` only if no review branch is required. Otherwise create a branch and PR, review, then merge.
6. Visit the GitHub `VERSION` file to confirm it reads `1.1.1`. Source upload does not upgrade any running container. On Proxmox, pull the source, verify tests and make an independently verified backup before updating a live LXC.

## Git source synchronization (Proxmox host, after publication)

```bash
cd /root/netsec-test-source
git status --short
# Stop if this shows local changes: review/commit them first.
git pull --ff-only origin main
cat VERSION
bash ci/check.sh
```

The `scripts/proxmox-setup.sh` host wizard only creates **new** LXCs and deliberately refuses existing IDs. For your in-place deployment use `scripts/install-lxc.sh --upgrade` after backup and verified file transfer, not the fresh-install wizard. See `docs/MIGRATION.md`.
