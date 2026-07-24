# Running WP Maintenance on the server (Devin outpost)

This guide covers running the health check **on the target server** through a
Devin **outpost** worker — the same way the routine check is performed today.

> An *outpost* is a Devin worker that executes on your own infrastructure, so
> WP-CLI, the log files, and `openssl` are all evaluated against the real host.

## 1. Prerequisites on the server

- **WP-CLI** (`wp`) available on `PATH` (xCloud/OpenLiteSpeed hosts ship it).
- **Python 3.8+**.
- **WeasyPrint** for the PDF (optional but recommended):
  ```bash
  sudo apt-get install -y python3-weasyprint
  # ── or ──
  python3 -m pip install -r requirements.txt
  ```
- Ability to read `/var/log/auth.log` — i.e. run as **root** or as a user in
  the **`adm`** group (`sudo usermod -aG adm <user>`).

## 2. Get the code + configure

```bash
git clone https://github.com/varry-llc/WPMaintenance.git
cd WPMaintenance
cp config/healthcheck.env.example config/healthcheck.env
chmod 600 config/healthcheck.env
$EDITOR config/healthcheck.env     # EMAILIT_API_KEY, MAIL_TO, SSH_ALLOWLIST, SERVER_LABEL
```

`SSH_ALLOWLIST` should list only the IPs whose **key-based** logins are
expected — e.g. the xCloud control plane and your automation worker. A
**password-based root login always escalates to `[ALERT]`**, regardless of the
allowlist, because it means password root SSH is enabled.

## 3. Privileged access pattern

The daily cron runs as root directly. When running interactively as an
unprivileged user via a pseudo-user (e.g. `devinoutpost`) that has `sudo`,
invoke the orchestrator like this so `auth.log` is readable and WeasyPrint
(installed under your user) is importable:

```bash
sudo env \
  PYTHONPATH="$HOME/.local/lib/python3.<minor>/site-packages" \
  bin/healthcheck.sh --send
```

If WeasyPrint is installed system-wide (`apt install python3-weasyprint`) you
can drop the `PYTHONPATH` line entirely.

## 4. First run (recommended: no e-mail yet)

```bash
sudo bin/healthcheck.sh --no-send
ls -l reports/                     # inspect the generated .md / .html / .pdf
```

When you're happy with the output, send for real:

```bash
sudo bin/healthcheck.sh --send
```

## 5. Verify delivery

`send_report.py` prints the EmailIt API response. A successful send returns
HTTP 200 with `"status": "accepted"` and an `id` like `em_…`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `auth=skipped` in collect output | Not running as root / not in `adm` group. |
| PDF skipped (`WeasyPrint unavailable`) | Install WeasyPrint + its pango/cairo system libs. |
| EmailIt `422 unverified domain` | Use a `MAIL_FROM` on a domain verified in EmailIt. |
| wp-cli permission warnings (e.g. `.litespeed_conf.dat`) | Harmless; they go to stderr and don't affect results. |
