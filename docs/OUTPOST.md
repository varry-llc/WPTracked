# Running WPTracked on the server (Devin outpost)

This guide covers running WPTracked **on the target server** through a Devin
**outpost** — the native way to execute against real infrastructure.

> A Devin **outpost** is a worker that runs on *your own* server, so WP-CLI, the
> log files, `openssl`, and the WordPress installs are all evaluated against the
> real host. WPTracked uses the outpost only as its execution environment — it
> does not reinvent any outpost management: you connect the outpost with Devin's
> native flow, then run the tool like any other command on the box.

## 0. Install & connect the outpost on the server (Devin-native)

WPTracked runs inside a Devin **outpost** — Devin's agent loop stays in the
cloud while every command runs on *your* server. Follow the official quickstart
(**https://docs.devin.ai/cloud/outposts/quickstart**); the steps are summarised
here. Nothing in this repo replaces that flow.

**Prerequisites**
- An organization with **Outposts enabled**.
- A **v3 API token** with the Outposts scopes
  (`account.outposts.orchestrator` and/or `account.outposts.machine`).
- The target server with your repo cloned and the [machine
  dependencies](https://docs.devin.ai/cloud/outposts/overview#machine-dependencies)
  plus WPTracked's own deps (Python 3.9+, WP-CLI, WeasyPrint — see §1).

**Steps**

1. **Install the Devin CLI** on the server:
   ```bash
   curl -fsSL https://cli.devin.ai/install.sh | bash
   ```
2. **Create an outpost** in Devin Cloud → **Settings → Environment → Outposts →
   "Create Outpost"**. Give it a name (e.g. `wp-hosts`) and choose the platform
   (**Linux** for a typical VPS).
3. **Start the worker** on the server so it serves that outpost's queue:
   ```bash
   devin worker start --outpost=<outpost_name>
   ```
   The worker opens an **outbound-only** HTTPS connection (no inbound ports /
   public IP needed) and executes sessions with your user's permissions. Run it
   under a user that can reach the sites and (via `sudo`) read `auth.log` — see
   §3.
4. **Start a session on the outpost.** In Devin Cloud the outpost now appears as
   a machine option; start a session on it and the worker on your server claims
   it. Confirm you're really on the box (`hostname`, `id -un`) before running the
   audit.

> Keep the worker running (e.g. under `systemd`, `tmux`, or `nohup`) if you want
> scheduled/automated runs to land on this server. If privileged steps need a
> password, provide it through Devin's **secret** mechanism (a session secret
> such as `SUDO_PASSWORD`) rather than typing it into a shell — see §3.

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
  audit every WordPress site under the web root(s). Sites are discovered
  **recursively** under `WWW_ROOT` (so nested docroots like `<site>/htdocs` are
  found); if your installs span several roots, set `WWW_ROOTS` to a
  comma-separated list (globs like `/home/*/htdocs` are expanded).
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

Only **one** thing needs elevated rights: reading `/var/log/auth.log` (owned
`syslog:adm`, mode `640`) for the SSH-intrusion analysis. Everything else runs
fine unprivileged. The app itself **never** calls `sudo`/`su` — it reads
`auth.log` only if the OS already permits it, otherwise it marks that section
*skipped* (never "clean"). So pick a run identity that can read it:

**Recommended — grant the run-user read access once, then no `sudo` ever:**

```bash
sudo usermod -aG adm <user>      # <user> = the account the outpost worker runs as
# open a new login session (or `newgrp adm`) so the group takes effect, then:
bin/healthcheck.sh --send        # auth.log readable, no password prompt
```

**Recommended for the recurring run — root cron/systemd** (see
[SCHEDULING.md](SCHEDULING.md) / `bin/install-cron.sh`). Cron launches the job
**as root**, so there is no `sudo` and no password at runtime at all.

> **Important — whose credential is whose.** The outpost worker executes every
> command as **the OS user that started `devin worker start`**. `sudo`
> authenticates *that* user with *that* user's password — a `SUDO_PASSWORD` for
> a *different* account (e.g. you provided `devinoutpost`'s password but the
> worker is running as `tlowing`) will be rejected. Check with `whoami` /
> `id -nG`. The clean fixes above (`adm` group, or root cron) avoid interactive
> `sudo` — and its "a terminal is required" pitfall — entirely.

If you must use `sudo` interactively (worker user *is* the one whose password
you have, and it's in `sudo`), preserve a user-installed WeasyPrint and any
Devin-provided secret env vars:

```bash
sudo -E env \
  PYTHONPATH="$HOME/.local/lib/python3.<minor>/site-packages" \
  bin/healthcheck.sh --send
```

If WeasyPrint is installed system-wide (`apt install python3-weasyprint`) drop
the `PYTHONPATH` line.

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
| **A live site is missing from the report** | Confirm it's under a scanned web root: the `discover: N site(s) across … : …` line (stderr) lists what was found. If it lives under a different root, add it to `WWW_ROOTS`. Nested docroots (`<site>/htdocs`, `/public_html`) are found automatically. Verify the install with `ls <path>/wp-load.php`. |
| **`sudo: incorrect password`** | The worker is running as a *different* user than the one whose `SUDO_PASSWORD` you provided. Run `whoami`; either supply that user's password, add it to `adm` (`sudo usermod -aG adm <user>`), or schedule via root cron. |
| **`sudo: a terminal is required to read the password`** | You invoked `sudo` from a non-interactive `su -c '… sudo …'` (no TTY). Use `adm` group / root cron instead of interactive `sudo`, or run from a real login shell. |
| `auth=skipped` in collect output | Not running as root / run-user not in `adm` group. Add it to `adm` or run the recurring job from root cron. |
| PDF skipped (`WeasyPrint unavailable`) | Install WeasyPrint + its pango/cairo system libs. |
| `MAIL_FROM is missing or not a valid address` | Set `MAIL_FROM` to `Name <addr@domain>` on a verified domain. |
| EmailIt `422 unverified domain` | Use a `MAIL_FROM` on a domain verified with your provider. |
| `Another WPTracked run holds …lock` | A previous run is still going; this run exits cleanly by design. |
| wp-cli permission warnings (e.g. `.litespeed_conf.dat`) | Harmless; they go to stderr and don't affect results. |

## Lessons learned

- **Match the run-user to the credential.** The outpost runs commands as the OS
  user that launched `devin worker start`. Decide that user up front and make
  *it* able to read `auth.log` (via `adm`) — don't rely on a `sudo` password
  that belongs to a different account. `whoami` / `id -nG` tell you where you
  stand.
- **A one-off report is one command, not a schedule change.** `bin/healthcheck.sh
  --send` runs a single pass and exits. You never shorten a cron frequency to
  "trigger" a run; frequency (cron/systemd/Automation) is entirely separate from
  the outbound-only worker connection.
- **Prefer root cron for recurring runs.** It sidesteps interactive `sudo`
  entirely and guarantees `auth.log` access.
- **Discovery must be layout-agnostic.** Real hosts nest docroots and spread
  sites across roots; discovery walks recursively and honours `WWW_ROOTS` so no
  site is silently missed. The stderr `discover:` line is your receipt of what
  was scanned.
