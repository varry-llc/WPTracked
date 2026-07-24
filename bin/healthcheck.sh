#!/usr/bin/env bash
# =============================================================================
# Varry LLC · WP Maintenance — health-check orchestrator
# -----------------------------------------------------------------------------
# Runs the full pipeline:
#     collect.py  ->  vuln_scan.py  ->  render_report.py  ->  send_report.py
#
# Usage:
#     bin/healthcheck.sh [--send | --no-send] [--dry-run] [--name NAME]
#
#   --send       Deliver the report by e-mail (default).
#   --no-send    Generate the report only; do not e-mail.
#   --dry-run    Build the e-mail payload but do not actually send.
#   --name NAME  Basename for the generated report files
#                (default: wp-health-YYYY-MM-DD).
#
# Configuration is read from config/healthcheck.env (see the .example file).
# Real environment variables always take precedence over that file.
#
# For full SSH auth.log analysis, run as root (the daily cron does) or as a
# user in the `adm` group. Otherwise that section is reported as "skipped".
# =============================================================================
set -euo pipefail

# --- Resolve repo root regardless of where we are invoked from ---------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# --- Load configuration ------------------------------------------------------
CONFIG_FILE="${WPM_CONFIG:-$REPO_ROOT/config/healthcheck.env}"
if [[ -f "$CONFIG_FILE" ]]; then
  # Export every KEY=VALUE in the file without overriding the real environment.
  set -a
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
  set +a
fi

# --- Defaults / arguments ----------------------------------------------------
DO_SEND=1
DRY_RUN=""
NAME=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --send)     DO_SEND=1 ;;
    --no-send)  DO_SEND=0 ;;
    --dry-run)  DRY_RUN="--dry-run" ;;
    --name)     NAME="$2"; shift ;;
    -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# --- Choose the Python interpreter -------------------------------------------
# Prefer a repo-local virtualenv, then an explicit override, then system python.
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  PYTHON="$REPO_ROOT/.venv/bin/python"
else
  PYTHON="${WPM_PYTHON:-python3}"
fi

OUT_DIR="$REPO_ROOT/out"
mkdir -p "$OUT_DIR" "$REPO_ROOT/reports"

echo "== Varry LLC · WP Maintenance =="
echo "repo:   $REPO_ROOT"
echo "python: $($PYTHON --version 2>&1)"
echo "user:   $(id -un) (root=$([[ $EUID -eq 0 ]] && echo yes || echo no))"
echo

# --- 1) Collect --------------------------------------------------------------
"$PYTHON" scripts/collect.py --out "$OUT_DIR/data.json"

# --- 2) Vulnerability + KEV scan --------------------------------------------
"$PYTHON" scripts/vuln_scan.py --data "$OUT_DIR/data.json" --out "$OUT_DIR/vuln.json"

# --- 3) Render branded Markdown / HTML / PDF --------------------------------
RENDER_ARGS=(--data "$OUT_DIR/data.json" --vuln "$OUT_DIR/vuln.json" --out-dir reports)
[[ -n "$NAME" ]] && RENDER_ARGS+=(--name "$NAME")
"$PYTHON" scripts/render_report.py "${RENDER_ARGS[@]}"

# Locate the manifest we just produced (newest one).
MANIFEST="$(ls -t reports/*.manifest.json | head -1)"
echo "manifest: $MANIFEST"

# --- 4) Send -----------------------------------------------------------------
if [[ "$DO_SEND" -eq 1 ]]; then
  "$PYTHON" scripts/send_report.py --manifest "$MANIFEST" $DRY_RUN
else
  echo "(--no-send) skipping e-mail delivery."
fi

echo
echo "Done."
