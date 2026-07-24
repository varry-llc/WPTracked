# Daily automation

Two supported ways to run WP Maintenance every day. Pick whichever fits your
operational model.

## Option A — Server cron (self-hosted)

Runs directly on the server as root (so `auth.log` is included). The API key
lives in `config/healthcheck.env` (kept `chmod 600`).

```bash
# Install a daily run at 07:15 local time
sudo bin/install-cron.sh --time "07:15"

# Change the time (re-run) or remove it
sudo bin/install-cron.sh --time "06:00"
sudo bin/install-cron.sh --uninstall
```

This writes `/etc/cron.d/varry-wp-maintenance`:

```cron
15 7 * * * root /path/to/WPMaintenance/bin/healthcheck.sh --send \
  >> /var/log/varry-wp-maintenance.log 2>&1
```

- Output/errors are appended to `/var/log/varry-wp-maintenance.log`.
- Ensure `config/healthcheck.env` exists with `EMAILIT_API_KEY` set, or the
  send step fails (the report is still generated under `reports/`).

**systemd-timer alternative** (equivalent, if you prefer timers to cron):

```ini
# /etc/systemd/system/varry-wpm.service
[Service]
Type=oneshot
ExecStart=/path/to/WPMaintenance/bin/healthcheck.sh --send
```
```ini
# /etc/systemd/system/varry-wpm.timer
[Timer]
OnCalendar=*-*-* 07:15:00
Persistent=true
[Install]
WantedBy=timers.target
```
```bash
sudo systemctl enable --now varry-wpm.timer
```

## Option B — Devin Automation (managed)

Instead of storing the API key on the server, run the check from a **scheduled
Devin outpost session**. Devin holds the credentials (EmailIt key, privileged
access) in its secret store, connects to the server on a schedule, runs
`bin/healthcheck.sh --send`, and can additionally post the result to Slack.

Set this up from the Devin app: create a **daily Automation** whose prompt is
essentially *"run WP Maintenance on the outpost and e-mail the report"*, and
attach the required secrets. See Devin's Automations documentation for the
exact steps. This is the better option when you don't want long-lived secrets
sitting in a file on the host.

## Which should I use?

| | Server cron | Devin Automation |
|---|---|---|
| Secret storage | file on host (`chmod 600`) | Devin secret store |
| Runs if Devin is unavailable | ✅ | ❌ |
| Central audit / Slack delivery | ❌ (host log only) | ✅ |
| Setup | one command | app-side schedule |
