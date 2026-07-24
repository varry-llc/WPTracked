# Running WPTracked on the server (Devin outpost)

This guide covers running WPTracked **on the target server** through a Devin
**outpost** — the native way to execute against real infrastructure.

> A Devin **outpost** is a worker that runs on *your own* server, so WP-CLI, the
> log files, `openssl`, and the WordPress installs are all evaluated against the
> real host. WPTracked uses the outpost only as its execution environment — it
> does not reinvent any outpost management: you connect the outpost with Devin's
> native flow, then run the tool like any other command on the box.

## 0. Connect the outpost (Devin-native)

Use Devin's built-in outpost workflow to attach a worker to your server — see
the official docs: **https://docs.devin.ai** (search "outpost"). Nothing in this
repo replaces that flow. Once your Devin session is running *on* the server
(you'll see the real hostname, e.g. from `hostname` / `id -un`), continue below.

If privileged steps need a password, provide it through Devin's **secret**
mechanism (a session secret such as `SUDO_PASSWORD`) rather than typing it into
a shell — see §3.

## 1. Prerequisites on the server

- **Python 3.9+**.
- **WP-CLI** (`wp`) on `PATH` — only needed for `WPT_MODE=server+wp`
  (xCloud/OpenLiteSpeed hosts ship it).
- **WeasyPrint** for the PDF (optional but recommended):
  ```bash
  sudo apt-get install -y python3-weasyprint
  # ── or ──
  python3 -m pip install -r requirements.txt
  ```
- **`openssl`** (TLS expiry) — present on virtually every server.
- Ability to read `/var/log/auth.log` — i.e. run as **root** or as a user in the
  **`adm`** group (`sudo usermod -aG adm <user>`).

## 2. Get the code + configure

```bash
git clone https://github.com/varry-llc/WPTracked.git
cd WPTracked
cp config/wptracked.env.example config/wptracked.env
chmod 600 config/wptracked.env
$EDITOR config/wptracked.env     # WPT_MODE, MAIL_TRANSPORT + creds, MAIL_TO, SSH_ALLOWLIST, SERVER_LABEL
```

Key choices:

- **`WPT_MODE`** — `server` for a plain VPS, or `server+wp` (default) to also
  audit every WordPress site under `WWW_ROOT`.
- **`MAIL_TRANSPORT`** — `emailit`, `smtp`, `sendgrid`, `mailgun`, `resend`, or
  `none`. See [the README](../README.md#mail-provider-agnostic).
- **`SSH_ALLOWLIST`** — only the IPs whose **key-based** logins are expected
  (e.g. the control plane and your automation worker). A **password-based root
  login always escalates to `[ALERT]`**, regardless of the allowlist.

### Supplying secrets via Devin (recommended)

Rather than writing the mail credential into `wptracked.env`, you can inject it
as an environment variable for the run — Devin session secrets are exported into
the shell, and real environment variables always win over the file:

```bash
# e.g. the mail key is provided as a Devin secret and exported in the session
sudo -E bin/healthcheck.sh --dry-run
```

## 3. Privileged access pattern

The scheduler runs as root directly. When running interactively as an
unprivileged pseudo-user (e.g. `devinoutpost`) that has `sudo`, invoke the
orchestrator so `auth.log` is readable and a user-installed WeasyPrint is
importable:

```bash
sudo env \
  PYTHONPATH="$HOME/.local/lib/python3.<minor>/site-packages" \
  bin/healthcheck.sh --send
```

If WeasyPrint is installed system-wide (`apt install python3-weasyprint`) drop
the `PYTHONPATH` line. Pass `-E` to preserve any Devin-provided secret env vars.

## 4. First run (recommended: no e-mail yet)

```bash
sudo bin/healthcheck.sh --no-send        # generate only
ls -l reports/                           # inspect the .md / .html / .pdf
sudo bin/healthcheck.sh --dry-run        # validate mail config + build payload, no send
```

When you're happy with the output, send for real:

```bash
sudo bin/healthcheck.sh --send
```

## 5. Verify delivery

`send_report.py` prints the transport result (e.g. `emailit HTTP 200 …`,
`smtp accepted via …`). A non-zero exit means **the report was not delivered** —
the report files still exist under `reports/`, so nothing is lost; fix the mail
config and re-run.

## 6. Schedule it

See [SCHEDULING.md](SCHEDULING.md) — install a `cron`/systemd schedule on the
server, or drive recurring runs with a **Devin Automation**.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `auth=skipped` in collect output | Not running as root / not in `adm` group. |
| PDF skipped (`WeasyPrint unavailable`) | Install WeasyPrint + its pango/cairo system libs. |
| `MAIL_FROM is missing or not a valid address` | Set `MAIL_FROM` to `Name <addr@domain>` on a verified domain. |
| EmailIt `422 unverified domain` | Use a `MAIL_FROM` on a domain verified with your provider. |
| `Another WPTracked run holds …lock` | A previous run is still going; this run exits cleanly by design. |
| wp-cli permission warnings (e.g. `.litespeed_conf.dat`) | Harmless; they go to stderr and don't affect results. |
