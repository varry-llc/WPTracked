#!/usr/bin/env bash
# =============================================================================
# WPTracked — health-check orchestrator  (by Varry LLC · https://wptracked.com)
# -----------------------------------------------------------------------------
# Runs the full read-only pipeline:
#     collect.py  ->  vuln_scan.py  ->  render_report.py  ->  send_report.py
#
# Usage:
#     bin/healthcheck.sh [--send | --no-send] [--dry-run] [--name NAME]
#
#   --send       Deliver the report by e-mail (default; honours MAIL_TRANSPORT).
#   --no-send    Generate the report only; do not e-mail.
#   --dry-run    Validate + build the e-mail payload but do not actually send.
#   --name NAME  Basename for the generated report files
#                (default: wptracked-YYYY-MM-DD).
#
# Configuration is read from config/wptracked.env (see the .example file).
# Real environment variables always take precedence over that file.
#
# WPT_MODE=server        -> host infrastructure + logs only (no WordPress)
# WPT_MODE=server+wp     -> everything (default)
# CHECK_*=0              -> disable an individual check (all on by default)
#
# For full SSH auth.log analysis, run as root (the scheduler does) or as a user
# in the `adm` group. Otherwise that section is reported as "skipped".
#
# This tool is strictly read-only: it never updates, edits, or reconfigures the
# server or any WordPress install.
# =============================================================================
set -euo pipefail

# Generated artefacts may embed host/site detail — keep them private.
umask 077

# --- Resolve repo root regardless of where we are invoked from ---------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# --- Load configuration ------------------------------------------------------
# Accept the new name, then the legacy name, then a WPT_CONFIG override.
CONFIG_FILE="${WPT_CONFIG:-}"
if [[ -z "$CONFIG_FILE" ]]; then
  if [[ -f "$REPO_ROOT/config/wptracked.env" ]]; then
    CONFIG_FILE="$REPO_ROOT/config/wptracked.env"
  elif [[ -f "$REPO_ROOT/config/healthcheck.env" ]]; then
    CONFIG_FILE="$REPO_ROOT/config/healthcheck.env"
  fi
fi
if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
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
    --name)     NAME="${2:-}"; shift ;;
    -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# --- Prevent overlapping scheduled runs (flock) ------------------------------
# Re-exec ourselves under an exclusive, non-blocking lock. If a previous run is
# still going, exit cleanly instead of piling up.
LOCK_FILE="${WPT_LOCK_FILE:-${TMPDIR:-/tmp}/wptracked.lock}"
if [[ -z "${WPT_LOCKED:-}" ]] && command -v flock >/dev/null 2>&1; then
  export WPT_LOCKED=1
  REEXEC=("$0" "$([[ "$DO_SEND" -eq 1 ]] && echo --send || echo --no-send)")
  [[ -n "$DRY_RUN" ]] && REEXEC+=(--dry-run)
  [[ -n "$NAME" ]] && REEXEC+=(--name "$NAME")
  exec flock -n "$LOCK_FILE" "${REEXEC[@]}" \
    || { echo "Another WPTracked run holds $LOCK_FILE — skipping." >&2; exit 0; }
fi

# --- Choose the Python interpreter -------------------------------------------
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  PYTHON="$REPO_ROOT/.venv/bin/python"
else
  PYTHON="${WPT_PYTHON:-${WPM_PYTHON:-python3}}"
fi

MODE="${WPT_MODE:-server+wp}"
OUT_DIR="$REPO_ROOT/out"
mkdir -p "$OUT_DIR" "$REPO_ROOT/reports"

echo "== ${BRAND_COMPANY:-Varry LLC} · ${BRAND_PROJECT:-WPTracked} =="
echo "repo:   $REPO_ROOT"
echo "mode:   $MODE"
echo "python: $($PYTHON --version 2>&1)"
echo "user:   $(id -un) (root=$([[ $EUID -eq 0 ]] && echo yes || echo no))"
echo

# --- 1) Collect --------------------------------------------------------------
"$PYTHON" scripts/collect.py --out "$OUT_DIR/data.json"

# --- 2) Vulnerability + KEV scan (WordPress modes only) ----------------------
if [[ "$MODE" != "server" && "${CHECK_WP_VULN:-1}" != "0" ]]; then
  "$PYTHON" scripts/vuln_scan.py --data "$OUT_DIR/data.json" --out "$OUT_DIR/vuln.json"
else
  echo '{}' > "$OUT_DIR/vuln.json"
  echo "(vuln scan skipped: mode=$MODE CHECK_WP_VULN=${CHECK_WP_VULN:-1})"
fi

# --- 3) Render branded Markdown / HTML / PDF --------------------------------
RENDER_ARGS=(--data "$OUT_DIR/data.json" --vuln "$OUT_DIR/vuln.json" --out-dir reports)
[[ -n "$NAME" ]] && RENDER_ARGS+=(--name "$NAME")
"$PYTHON" scripts/render_report.py "${RENDER_ARGS[@]}"

# Locate the manifest we just produced (newest one), robustly.
MANIFEST="$(find reports -maxdepth 1 -name '*.manifest.json' -printf '%T@ %p\n' \
            | sort -nr | head -1 | cut -d' ' -f2-)"
if [[ -z "$MANIFEST" ]]; then
  echo "ERROR: no report manifest produced." >&2
  exit 1
fi
echo "manifest: $MANIFEST"

# --- 4) Send -----------------------------------------------------------------
# The report artefacts already exist on disk, so a delivery failure never loses
# the report — it just surfaces as a non-zero exit here.
if [[ "$DO_SEND" -eq 1 ]]; then
  "$PYTHON" scripts/send_report.py --manifest "$MANIFEST" $DRY_RUN
else
  echo "(--no-send) skipping e-mail delivery."
fi

echo
echo "Done."
