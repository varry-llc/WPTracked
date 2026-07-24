<div align="center">
  <img src="assets/varry-logo.svg" alt="Varry LLC · WP Maintenance" height="72">
  <h1>WP Maintenance</h1>
  <p><strong>Varry LLC</strong> · automated server &amp; WordPress health checks with branded e-mail reporting</p>
</div>

---

`WP Maintenance` runs a routine, **read-only** health check across every
WordPress site on a server, decides whether the result is `[HEALTHY]` or
`[ALERT]`, and e-mails a Varry LLC–branded report (HTML body + PDF attachment).

It is designed to run **on the server** — either from a daily `cron` job or
from a scheduled **Devin outpost** session.

## What it checks

| Area | Checks |
|---|---|
| **Host infrastructure** | Disk usage (`df`) + inode pressure, TLS certificate expiry per site domain, pending OS/security updates (apt), reboot-required flag |
| **WordPress core** | `wp core verify-checksums` on every install (tamper detection) + core version |
| **Plugins & themes** | Full inventory per site, available updates, and a **known-vulnerability scan** against [wpvulnerability.net](https://www.wpvulnerability.net) (CVE + Patchstack sources) |
| **CVE / KEV** | Every matched CVE is cross-referenced against the **CISA KEV** (Known Exploited Vulnerabilities) catalog |
| **Logs** | OpenLiteSpeed error logs, web access-log HTTP-status/threat summary (5xx, wp-login, xmlrpc, user-enum, `.env`/`.git` probes), and SSH `auth.log` (brute-force + successful-login analysis) |

The overall verdict is `[ALERT]` if any critical condition is found
(core tampering, a matching vulnerability/KEV, disk ≥ 90%, cert expiring soon,
5xx errors, or password-based root SSH), otherwise `[HEALTHY]`.

## How it works

```
                                          ┌── reports/<name>.md    (plain / e-mail text)
collect.py ──▶ vuln_scan.py ──▶ render_report.py ──▶ reports/<name>.html  (branded e-mail body)
   │               │                 │            └── reports/<name>.pdf   (branded attachment)
 data.json      vuln.json         verdict + manifest
                                          │
                                          └──▶ send_report.py ──▶ EmailIt API
```

Each stage writes JSON that the next stage consumes, so you can run/inspect any
stage on its own. `bin/healthcheck.sh` wires them together.

| Script | Role |
|---|---|
| [`scripts/collect.py`](scripts/collect.py) | Gather all raw data into `out/data.json` (read-only) |
| [`scripts/vuln_scan.py`](scripts/vuln_scan.py) | Match inventory vs wpvulnerability.net + CISA KEV → `out/vuln.json` |
| [`scripts/render_report.py`](scripts/render_report.py) | Apply verdict rules; render Markdown + branded HTML + PDF |
| [`scripts/send_report.py`](scripts/send_report.py) | Deliver the report via the EmailIt API |
| [`bin/healthcheck.sh`](bin/healthcheck.sh) | Orchestrator (`collect → scan → render → send`) |
| [`bin/install-cron.sh`](bin/install-cron.sh) | Install/remove the daily cron entry |

## Quickstart

```bash
git clone https://github.com/varry-llc/WPMaintenance.git
cd WPMaintenance

# 1. Configure
cp config/healthcheck.env.example config/healthcheck.env
chmod 600 config/healthcheck.env
$EDITOR config/healthcheck.env      # set EMAILIT_API_KEY, MAIL_TO, SSH_ALLOWLIST, …

# 2. Install the one Python dependency (PDF rendering)
python3 -m pip install -r requirements.txt      # or: sudo apt install python3-weasyprint

# 3. Run it (as root so auth.log is included)
sudo bin/healthcheck.sh --send
```

Generate the report **without** e-mailing (handy for a first run):

```bash
sudo bin/healthcheck.sh --no-send        # writes reports/wp-health-<date>.{md,html,pdf}
sudo bin/healthcheck.sh --dry-run        # builds the e-mail but does not send
```

## Requirements

- **Python 3.8+** and **[WP-CLI](https://wp-cli.org/)** (`wp`) on `PATH`.
- **WeasyPrint** for the PDF attachment (`requirements.txt`). System libraries:
  `libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0`.
  *Without it the run still produces the Markdown + HTML report; only the PDF is skipped.*
- **`openssl`** (TLS expiry) — present on virtually every server.
- **Root** (or a user in the `adm` group) to read `/var/log/auth.log`.
- An **[EmailIt](https://emailit.com/docs)** API key and a verified sender domain.

## Configuration

All settings live in `config/healthcheck.env` (git-ignored). Every value can
also be provided as a real environment variable, which always wins. See
[`config/healthcheck.env.example`](config/healthcheck.env.example) for the full,
commented list — the essentials:

| Variable | Purpose |
|---|---|
| `EMAILIT_API_KEY` | EmailIt Bearer token (**required to send**) |
| `MAIL_FROM` / `MAIL_TO` | Sender (verified domain) / recipients |
| `SSH_ALLOWLIST` | IPs whose key-based logins are expected (control plane, worker) |
| `SERVER_LABEL` | Friendly server name shown in the report |
| `DISK_*` / `SSL_*` | Warning/alert thresholds |
| `BRAND_COMPANY` / `BRAND_PROJECT` / `BRAND_LOGO` | Branding |

## Example output

An example run is committed as
[`reports/sample-wp-health-report.md`](reports/sample-wp-health-report.md) with
the branded PDF at
[`reports/sample-wp-health-report.pdf`](reports/sample-wp-health-report.pdf).

## Documentation

- **[docs/OUTPOST.md](docs/OUTPOST.md)** — running this on the server through a Devin outpost (privileged access, first-run walkthrough).
- **[docs/SCHEDULING.md](docs/SCHEDULING.md)** — daily automation: server `cron` **or** a Devin Automation.
- **[docs/REPORT.md](docs/REPORT.md)** — what's in the report, the verdict rules, and the branding.

## Security & safety

- **Read-only.** Nothing here updates WordPress, changes server config, or
  installs packages. It only *reports*.
- **No secrets in git.** `config/healthcheck.env` and everything in `out/` /
  generated `reports/*` are git-ignored. Keep the env file `chmod 600`.
- A failed vulnerability-feed lookup is reported as *incomplete*, never as a
  clean bill of health.

---

<div align="center"><sub>© Varry LLC · WP Maintenance</sub></div>
