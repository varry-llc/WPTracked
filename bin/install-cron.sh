#!/usr/bin/env bash
# =============================================================================
# Varry LLC · WP Maintenance — daily cron installer
# -----------------------------------------------------------------------------
# Installs a systemd-cron / crontab entry that runs the health check once a day
# and e-mails the branded report.
#
# Run as root so the job can read /var/log/auth.log (SSH intrusion analysis):
#     sudo bin/install-cron.sh [--time "07:15"] [--uninstall]
#
#   --time HH:MM   Local time to run daily (default 07:15).
#   --uninstall    Remove the installed cron entry.
#
# The job is written to /etc/cron.d/varry-wp-maintenance and invokes
# bin/healthcheck.sh from this checkout. Configuration (incl. the EmailIt API
# key) is read from config/healthcheck.env — make sure that file exists and is
# chmod 600 before enabling the schedule.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRON_FILE="/etc/cron.d/varry-wp-maintenance"
RUN_TIME="07:15"
UNINSTALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --time) RUN_TIME="$2"; shift ;;
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
RUN_USER="${SUDO_USER:-root}"

cat > "$CRON_FILE" <<EOF
# Varry LLC · WP Maintenance — daily WordPress & server health check
# Managed by bin/install-cron.sh — edit --time and re-run to change.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=""
$MM $HH * * * root $REPO_ROOT/bin/healthcheck.sh --send >> /var/log/varry-wp-maintenance.log 2>&1
EOF
chmod 644 "$CRON_FILE"

echo "Installed daily health check at $RUN_TIME:"
echo "  $CRON_FILE"
echo "  logs -> /var/log/varry-wp-maintenance.log"
echo
echo "Reminder: ensure $REPO_ROOT/config/healthcheck.env exists (chmod 600) with"
echo "EMAILIT_API_KEY set, or the daily e-mail send will fail."
