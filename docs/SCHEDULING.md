# Scheduling recurring runs

Frequency is a **scheduler** concern — the WPTracked audit itself always does a
single read-only pass and exits. Overlapping runs are prevented by the `flock`
in `bin/healthcheck.sh`, so even an aggressive schedule can't pile up.

Pick whichever model fits your operations.

## Option A — Server cron (self-hosted)

Runs directly on the server as root (so `auth.log` is included). Credentials
live in `config/wptracked.env` (kept `chmod 600`).

Frequency/time come from `config/wptracked.env`
(`SCHEDULE_FREQUENCY`, `SCHEDULE_TIME`, `SCHEDULE_DOW`, `SCHEDULE_DOM`) and can be
overridden on the command line:

```bash
# Use the schedule from config
sudo bin/install-cron.sh

# Or override: daily at 06:00, weekly on Monday, hourly, monthly on the 1st
sudo bin/install-cron.sh --frequency daily  --time "06:00"
sudo bin/install-cron.sh --frequency weekly --time "07:15" --dow 1
sudo bin/install-cron.sh --frequency hourly
sudo bin/install-cron.sh --frequency monthly --time "07:15" --dom 1

# Remove it
sudo bin/install-cron.sh --uninstall
```

This writes `/etc/cron.d/wptracked`, e.g. for a daily run:

```cron
15 7 * * * root /path/to/WPTracked/bin/healthcheck.sh --send \
  >> /var/log/wptracked.log 2>&1
```

- Output/errors are appended to `/var/log/wptracked.log`.
- Ensure `config/wptracked.env` exists with a working `MAIL_TRANSPORT`, or the
  send step fails (the report is still generated under `reports/`).
- **Missed schedules:** `cron.d` does not run past-due jobs. If the host may be
  off at the scheduled time and you need catch-up, use the systemd timer with
  `Persistent=true` (below), which runs a missed job at next boot.

### systemd-timer alternative (catch-up + missed runs)

```ini
# /etc/systemd/system/wptracked.service
[Service]
Type=oneshot
ExecStart=/path/to/WPTracked/bin/healthcheck.sh --send
```
```ini
# /etc/systemd/system/wptracked.timer
[Timer]
OnCalendar=*-*-* 07:15:00
Persistent=true          # run a missed occurrence at next boot
[Install]
WantedBy=timers.target
```
```bash
sudo systemctl enable --now wptracked.timer
systemctl list-timers wptracked.timer     # confirm next run
```

## Option B — Devin Automation (managed)

Instead of storing credentials on the server, run the check from a **scheduled
Devin outpost session**. Devin holds the credentials (mail key, privileged
access) in its secret store, connects to the server on a schedule, runs
`bin/healthcheck.sh --send`, and can additionally post the result to Slack.

Set this up from the Devin app: create an **Automation** whose prompt is
essentially *"run WPTracked on the outpost and e-mail the report"*, attach the
required secrets, and choose the cadence. See Devin's Automations docs at
**https://docs.devin.ai**. This is the better option when you don't want
long-lived secrets in a file on the host, or want central Slack delivery.

## Which should I use?

| | Server cron / timer | Devin Automation |
|---|---|---|
| Secret storage | file on host (`chmod 600`) | Devin secret store |
| Runs if Devin is unavailable | ✅ | ❌ |
| Missed-run catch-up | ✅ (systemd `Persistent`) | ✅ (managed) |
| Central audit / Slack delivery | ❌ (host log only) | ✅ |
| Setup | one command | app-side schedule |
