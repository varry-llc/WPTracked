#!/usr/bin/env bash
# =============================================================================
# WPTracked — schedule installer  (by Varry LLC · https://wptracked.com)
# -----------------------------------------------------------------------------
# Installs a /etc/cron.d entry that runs the health check on a schedule and
# e-mails the branded report. Frequency + time come from config/wptracked.env
# (SCHEDULE_FREQUENCY / SCHEDULE_TIME / SCHEDULE_DOW / SCHEDULE_DOM) but can be
# overridden on the command line.
#
# Run as root so the job can read /var/log/auth.log (SSH intrusion analysis):
#     sudo bin/install-cron.sh [--frequency daily] [--time "07:15"] [--uninstall]
#
#   --frequency F   hourly | daily | weekly | monthly   (default: daily)
#   --time HH:MM    local time to run (ignored for hourly; default 07:15)
#   --dow N         day-of-week 0-6 (Sun-Sat) for weekly  (default 1 = Mon)
#   --dom N         day-of-month 1-28 for monthly         (default 1)
#   --uninstall     remove the installed schedule
#
# Frequency is a *scheduler* concern — the audit itself always does one pass and
# exits. Overlap is prevented by the flock in bin/healthcheck.sh.
#
# The job invokes bin/healthcheck.sh from this checkout. Configuration (incl.
# any mail credential) is read from config/wptracked.env — make sure that file
# exists and is chmod 600 before enabling the schedule.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRON_FILE="/etc/cron.d/wptracked"
LOG_FILE="/var/log/wptracked.log"

# Defaults, overridable by config then CLI.
if [[ -f "$REPO_ROOT/config/wptracked.env" ]]; then
  # shellcheck disable=SC1091
  source "$REPO_ROOT/config/wptracked.env"
fi
FREQUENCY="${SCHEDULE_FREQUENCY:-daily}"
RUN_TIME="${SCHEDULE_TIME:-07:15}"
DOW="${SCHEDULE_DOW:-1}"
DOM="${SCHEDULE_DOM:-1}"
UNINSTALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --frequency) FREQUENCY="$2"; shift ;;
    --time) RUN_TIME="$2"; shift ;;
    --dow) DOW="$2"; shift ;;
    --dom) DOM="$2"; shift ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (needed to write $CRON_FILE and read auth.log)." >&2
  exit 1
fi

if [[ "$UNINSTALL" -eq 1 ]]; then
  rm -f "$CRON_FILE"
  echo "Removed $CRON_FILE"
  exit 0
fi

HH="${RUN_TIME%%:*}"
MM="${RUN_TIME##*:}"

case "$FREQUENCY" in
  hourly)  SPEC="0 * * * *" ;;
  daily)   SPEC="$MM $HH * * *" ;;
  weekly)  SPEC="$MM $HH * * $DOW" ;;
  monthly) SPEC="$MM $HH $DOM * *" ;;
  *) echo "Unknown --frequency '$FREQUENCY' (hourly|daily|weekly|monthly)" >&2; exit 2 ;;
esac

cat > "$CRON_FILE" <<EOF
# WPTracked — $FREQUENCY WordPress & server health check (by Varry LLC)
# Managed by bin/install-cron.sh — edit options and re-run to change.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=""
$SPEC root $REPO_ROOT/bin/healthcheck.sh --send >> $LOG_FILE 2>&1
EOF
chmod 644 "$CRON_FILE"

echo "Installed $FREQUENCY health check:"
echo "  schedule: $SPEC"
echo "  file:     $CRON_FILE"
echo "  logs:     $LOG_FILE"
echo
echo "Reminder: ensure $REPO_ROOT/config/wptracked.env exists (chmod 600) with a"
echo "mail transport configured, or the scheduled e-mail send will fail."
