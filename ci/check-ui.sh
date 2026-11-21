#!/usr/bin/env bash
set -Eeuo pipefail
node --check app/jimmy-ui.js
node --check app/netsec-v13.js
node --check app/mobile-ui.js
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python3 - "$tmp" <<'PY'
import pathlib,re,sys
s=pathlib.Path('app/index.html').read_text()
blocks=re.findall(r'<script(?:\s[^>]*)?>([\s\S]*?)</script>',s)
code=[b for b in blocks if b.strip()]
if not code:raise SystemExit('Missing inline dashboard JS')
for i,script in enumerate(code):
    pathlib.Path(sys.argv[1],f'inline-{i}.js').write_text(script)
print('Extracted',len(code),'inline JS block(s) for syntax validation')
PY
for js in "$tmp"/*.js; do node --check "$js"; done
