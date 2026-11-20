# Optional native Open WebUI + Ollama backend (no Docker)

NetSec runs and CrowdSec blocks attacks **without** AI. Jimmy requires an existing Open WebUI API endpoint with a dedicated API key and JSON-capable model. Users who already operate Open WebUI/Ollama should skip this appendix and use `/etc/netsec-ai.env` as described in the main README.

This optional design uses a **separate Debian LXC or Linux machine** for model inference; do not try to run a multi-gigabyte Ollama model inside NetSec's 2 GB monitoring container. Provision enough RAM and optionally GPU passthrough according to the model and hardware. This appendix assumes a fresh Debian 12/13 Linux guest under your own administration; GPU installation depends on hardware and is not automated here.

## A. Ollama native systemd service

Inside the new AI Linux guest as root:

```bash
apt-get update
apt-get install -y curl ca-certificates python3 python3-venv python3-pip openssl
curl -fsSL https://ollama.com/install.sh -o /root/ollama-install.sh
# Review the vendor install script before executing.
bash /root/ollama-install.sh
systemctl enable --now ollama
systemctl status ollama --no-pager
curl -fsS http://127.0.0.1:11434/api/tags
```

Select a model that fits the available RAM or GPU memory, then:

```bash
ollama pull MODEL_NAME
ollama list
```

Use an actual Ollama model identifier for `MODEL_NAME`; consult the current Ollama library. Keep the Ollama API on `127.0.0.1:11434` if WebUI lives on the same machine, rather than internet-exposing it.

## B. Open WebUI in a native Python virtual environment

The official Open WebUI instructions currently support Python 3.11 and 3.12. Debian 12's Python 3.11 is supported; PyPI wheels pull a significant ML/PyTorch stack. On CPU-only machines, installing CPU PyTorch first avoids downloading the CUDA variant.

```bash
useradd --system --user-group --home-dir /var/lib/open-webui --shell /usr/sbin/nologin openwebui
install -d -o openwebui -g openwebui -m 0700 /var/lib/open-webui/data
python3 -m venv /opt/open-webui-venv
/opt/open-webui-venv/bin/pip install --upgrade pip
# CPU-only guests may run the next line; skip for GPU-accelerated environments.
/opt/open-webui-venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
/opt/open-webui-venv/bin/pip install open-webui
```

Configure a persistent signing key and Ollama base URL:

```bash
install -m 600 -o root -g root /dev/null /etc/open-webui.env
printf 'WEBUI_SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> /etc/open-webui.env
cat >> /etc/open-webui.env <<'EOF'
DATA_DIR=/var/lib/open-webui/data
OLLAMA_BASE_URL=http://127.0.0.1:11434
EOF
cat > /etc/systemd/system/open-webui.service <<'EOF'
[Unit]
Description=Native Open WebUI
After=network-online.target ollama.service
Wants=network-online.target

[Service]
User=openwebui
Group=openwebui
WorkingDirectory=/var/lib/open-webui
EnvironmentFile=/etc/open-webui.env
ExecStart=/opt/open-webui-venv/bin/open-webui serve --host 0.0.0.0 --port 8080
Restart=on-failure
RestartSec=8
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now open-webui.service
journalctl -u open-webui.service -n 30 --no-pager
```

`openssl` is required for the generated key (install `openssl` if it isn't already present). **Bind WebUI on your LAN only if protected**: port 8080 should not be router-forwarded. Put it behind an authenticated HTTPS reverse proxy, or use a strict host/LXC firewall policy for LAN access. Set up the initial Open WebUI admin account through its UI and ensure external API-key access is enabled for a dedicated NetSec analyst account.

For `OWUI_URL`, prefer your authenticated HTTPS Open WebUI hostname, e.g. `https://ai.example.org`. If using direct LAN HTTP, the NetSec code only accepts a private numeric IP because model API keys would otherwise risk exposure; HTTPS is strongly preferred even on a LAN.

## C. Connect NetSec to the model

Inside **NetSec LXC**, not the AI container:

```bash
cp /root/netsec-community-proxmox-v1.1/config/netsec-ai.env.example /etc/netsec-ai.env
nano /etc/netsec-ai.env
chown root:statusdash /etc/netsec-ai.env
chmod 640 /etc/netsec-ai.env
systemctl enable --now netsec-ai-worker.service
journalctl -u netsec-ai-worker -n 50 --no-pager
```

Fill the file with actual `OWUI_URL`, `OWUI_MODEL` and the NetSec analyst's `OWUI_KEY` without sharing that key. Jimmy uses `POST /api/chat/completions` through Open WebUI. The model must respond with JSON; the code will retry once with a shorter context if it gets malformed JSON. It will not autonomously patch, ban or change server configuration.

Official documentation:
- <https://ollama.com/download/linux>
- <https://docs.openwebui.com/getting-started/quick-start/>
