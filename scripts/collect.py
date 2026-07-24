#!/usr/bin/env python3
"""
collect.py — gather raw server + WordPress health data into a single JSON file.

This is the *data collection* stage of the Varry LLC · WP Maintenance pipeline.
It performs **read-only** inspection only; it never changes server or site state.

What it collects
----------------
  Host infrastructure : disk usage, inode pressure, TLS certificate expiry per
                        site domain, pending OS/security updates, reboot flag.
  WordPress           : discovered installs under WWW_ROOT, core version,
                        `wp core verify-checksums`, and the full plugin/theme
                        inventory (with available-update info).
  Logs                : OpenLiteSpeed per-vhost error-log sizes, web access-log
                        HTTP status distribution + suspicious endpoints, and —
                        when run as root — a summary of /var/log/auth.log
                        (brute-force attempts and successful logins).

Output
------
  A JSON document (see --out) consumed by vuln_scan.py and render_report.py.

Notes
-----
  * auth.log is root-readable only. Run this as root (the daily cron does) to
    include SSH intrusion analysis; otherwise that section is marked skipped.
  * wp-cli is invoked with --allow-root automatically when running as root.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
import re
import shutil
import ssl
import socket
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run a command, returning (exit_code, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001 - collection must be resilient
        return 1, "", str(e)


def wp(site_path: str, args: list[str], timeout: int = 90) -> str:
    """Invoke wp-cli for a site and return stdout (stderr discarded).

    `--allow-root` is added when we are root so wp-cli will operate on site
    files owned by the per-site users. wp-cli emits the odd PHP warning to
    stderr (e.g. the LiteSpeed object-cache drop-in in CLI context); those are
    intentionally ignored here.
    """
    base = ["wp", *args, f"--path={site_path}"]
    if os.geteuid() == 0:
        base.append("--allow-root")
    _, out, _ = run(base, timeout=timeout)
    return out.strip()


def wp_json(site_path: str, args: list[str]):
    """Like wp() but parse JSON output, tolerating leading warning noise."""
    out = wp(site_path, [*args, "--format=json"])
    i = out.find("[")
    if i > 0:
        out = out[i:]
    try:
        return json.loads(out)
    except Exception:  # noqa: BLE001
        return []


# --------------------------------------------------------------------------- #
# Host infrastructure
# --------------------------------------------------------------------------- #

def collect_disk() -> tuple[list[dict], int | None]:
    """Return per-filesystem usage for real block devices + root inode %."""
    rows: list[dict] = []
    code, out, _ = run(["df", "-Ph"])
    if code == 0:
        for line in out.splitlines()[1:]:
            f = line.split()
            if len(f) < 6:
                continue
            # Only report real devices (skip tmpfs/overlay/etc.)
            if not (f[0].startswith("/dev/") or f[0] == "overlay"):
                continue
            rows.append({
                "filesystem": f[0], "size": f[1], "used": f[2],
                "avail": f[3], "use_pct": int(f[4].rstrip("%")), "mount": f[5],
            })
    inode_pct = None
    code, out, _ = run(["df", "-Pi", "/"])
    if code == 0:
        parts = out.splitlines()[1].split()
        if len(parts) >= 5:
            try:
                inode_pct = int(parts[4].rstrip("%"))
            except ValueError:
                pass
    return rows, inode_pct


def collect_ssl(domains: list[str]) -> list[dict]:
    """Fetch and summarise the served TLS certificate for each domain."""
    results = []
    now = dt.datetime.now(dt.timezone.utc)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for d in domains:
        entry = {"domain": d}
        try:
            with socket.create_connection((d, 443), timeout=15) as sock:
                with ctx.wrap_socket(sock, server_hostname=d) as ss:
                    # binary DER -> parse dates via ssl helper on a reconnect
                    cert_bin = ss.getpeercert(binary_form=True)
            # Parse with openssl for robust field extraction.
            code, out, _ = run(["openssl", "x509", "-noout", "-subject",
                                "-issuer", "-enddate", "-startdate"],
                               timeout=15)
            # openssl needs the cert on stdin; redo via pipe:
            p = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer",
                 "-enddate", "-startdate"],
                input=ssl.DER_cert_to_PEM_cert(cert_bin),
                capture_output=True, text=True, timeout=15,
            )
            fields = dict(
                re.match(r"(\w+)=(.*)", ln.strip()).groups()
                for ln in p.stdout.splitlines() if "=" in ln
            )
            not_after = fields.get("notAfter", "")
            exp = None
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
                try:
                    exp = dt.datetime.strptime(not_after, fmt).replace(
                        tzinfo=dt.timezone.utc)
                    break
                except ValueError:
                    continue
            entry.update({
                "subject": fields.get("subject", ""),
                "issuer": fields.get("issuer", ""),
                "not_before": fields.get("notBefore", ""),
                "not_after": not_after,
                "days_left": (exp - now).days if exp else None,
            })
        except Exception as e:  # noqa: BLE001
            entry["error"] = str(e)
        results.append(entry)
    return results


def collect_updates() -> dict:
    """Summarise pending apt updates using update-notifier's apt-check."""
    info: dict = {"updates": None, "security": None, "esm": None,
                  "reboot_required": os.path.exists("/var/run/reboot-required"),
                  "raw": ""}
    checker = "/usr/lib/update-notifier/apt-check"
    if os.path.exists(checker):
        # Machine format prints "updates;security" on stderr.
        _, _, err = run([checker])
        m = re.match(r"\s*(\d+);(\d+)", err or "")
        if m:
            info["updates"] = int(m.group(1))
            info["security"] = int(m.group(2))
        # Human-readable form exposes the ESM-only count.
        _, hout, herr = run([checker, "--human-readable"])
        info["raw"] = (hout or herr or "").strip()
        m = re.search(r"(\d+)\s+.*ESM", info["raw"])
        if m:
            info["esm"] = int(m.group(1))
    return info


# --------------------------------------------------------------------------- #
# WordPress
# --------------------------------------------------------------------------- #

def discover_sites(www_root: str) -> list[dict]:
    """Find WordPress installs under www_root (dirs containing wp-load.php)."""
    sites = []
    root = Path(www_root)
    if not root.is_dir():
        return sites
    for child in sorted(root.iterdir()):
        if child.is_dir() and (child / "wp-load.php").exists():
            sites.append({"slug": child.name, "path": str(child),
                          "url": f"https://{child.name}"})
    return sites


def collect_site(site: dict) -> dict:
    """Collect version, checksum integrity and plugin/theme inventory."""
    path = site["path"]
    site["wp_version"] = wp(path, ["core", "version"]) or None
    checksum_out = wp(path, ["core", "verify-checksums"])
    combined = checksum_out.lower()
    site["checksums_ok"] = "success" in combined or "verifies against" in combined
    site["checksums_detail"] = checksum_out.splitlines()[-1] if checksum_out else ""
    site["plugins"] = [
        p for p in wp_json(path, ["plugin", "list",
            "--fields=name,status,version,update,update_version,auto_update"])
        if p.get("status") != "dropin"
    ]
    site["themes"] = wp_json(path, ["theme", "list",
        "--fields=name,status,version,update,update_version"])
    return site


# --------------------------------------------------------------------------- #
# Logs
# --------------------------------------------------------------------------- #

def collect_web_logs(sites: list[dict], log_dir: str = "/var/log/lsws") -> dict:
    """OpenLiteSpeed error-log sizes + access-log status/threat summary."""
    out = {"ols_error_logs": [], "access": []}
    ld = Path(log_dir)
    for s in sites:
        slug = s["slug"]
        err = ld / f"{slug}-error.log"
        if err.exists():
            out["ols_error_logs"].append(
                {"site": slug, "bytes": err.stat().st_size})
        acc = ld / f"{slug}-access.log"
        if not acc.exists():
            continue
        status: dict[str, int] = {}
        suspicious = {"wp-login": 0, "xmlrpc": 0, "user-enum": 0,
                      "env-probe": 0, "5xx": 0}
        total = 0
        try:
            with acc.open(errors="replace") as fh:
                for line in fh:
                    total += 1
                    parts = line.split()
                    if len(parts) > 8:
                        code = parts[8]
                        status[code] = status.get(code, 0) + 1
                        if code.startswith("5"):
                            suspicious["5xx"] += 1
                    low = line.lower()
                    if "wp-login.php" in low and '"post' in low:
                        suspicious["wp-login"] += 1
                    if "xmlrpc.php" in low:
                        suspicious["xmlrpc"] += 1
                    if "/wp-json/wp/v2/users" in low:
                        suspicious["user-enum"] += 1
                    if "/.env" in low or "/.git" in low:
                        suspicious["env-probe"] += 1
        except Exception:  # noqa: BLE001
            pass
        out["access"].append({"site": slug, "total": total,
                              "status_counts": status, "suspicious": suspicious})
    return out


def collect_auth_log(path: str = "/var/log/auth.log") -> dict:
    """Summarise SSH auth activity. Requires root to read the file."""
    res: dict = {"available": False}
    p = Path(path)
    if not (p.exists() and os.access(path, os.R_OK)):
        res["reason"] = "not readable (run as root to include SSH analysis)"
        return res
    invalid_user = failed = failed_root = 0
    accepted: dict[tuple, int] = {}
    attacker_ips: dict[str, int] = {}
    invalid_names: dict[str, int] = {}
    root_pw: dict[str, int] = {}
    first_ts = last_ts = None
    re_accept = re.compile(r"Accepted (\w+) for (\S+) from (\S+)")
    re_failfrom = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    re_invalid = re.compile(r"Invalid user (\S+) from (\S+)")
    try:
        with p.open(errors="replace") as fh:
            for line in fh:
                ts = line[:15].strip()
                if ts:
                    first_ts = first_ts or ts
                    last_ts = ts
                if "Invalid user" in line:
                    invalid_user += 1
                    m = re_invalid.search(line)
                    if m:
                        invalid_names[m.group(1)] = invalid_names.get(m.group(1), 0) + 1
                if "Failed password" in line:
                    failed += 1
                    m = re_failfrom.search(line)
                    if m:
                        if m.group(1) == "root":
                            failed_root += 1
                        attacker_ips[m.group(2)] = attacker_ips.get(m.group(2), 0) + 1
                m = re_accept.search(line)
                if m:
                    method, user, ip = m.groups()
                    accepted[(method, user, ip)] = accepted.get((method, user, ip), 0) + 1
                    if method == "password" and user == "root":
                        root_pw[ip] = root_pw.get(ip, 0) + 1
    except Exception as e:  # noqa: BLE001
        res["reason"] = str(e)
        return res

    def top(d, n=10):
        return [{"key": k, "count": v}
                for k, v in sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]]

    res.update({
        "available": True,
        "window": {"from": first_ts, "to": last_ts},
        "invalid_user": invalid_user,
        "failed_password": failed,
        "failed_root": failed_root,
        "accepted": [{"method": k[0], "user": k[1], "ip": k[2], "count": v}
                     for k, v in sorted(accepted.items(), key=lambda kv: kv[1], reverse=True)],
        "top_attacker_ips": [{"ip": x["key"], "count": x["count"]} for x in top(attacker_ips)],
        "invalid_usernames": [{"name": x["key"], "count": x["count"]} for x in top(invalid_names, 15)],
        "root_password_logins": [{"ip": k, "count": v} for k, v in root_pw.items()],
    })
    return res


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="Collect WP/server health data as JSON.")
    ap.add_argument("--out", default="out/data.json", help="output JSON path")
    ap.add_argument("--www-root", default=os.environ.get("WWW_ROOT", "/var/www"))
    ap.add_argument("--server-label", default=os.environ.get("SERVER_LABEL", ""))
    args = ap.parse_args()

    if not shutil.which("wp"):
        print("WARNING: wp-cli not found on PATH; WordPress checks will be empty.",
              file=sys.stderr)

    sites = discover_sites(args.www_root)
    for s in sites:
        collect_site(s)

    disk, inode_pct = collect_disk()
    data = {
        "meta": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "server_label": args.server_label or socket.gethostname(),
            "hostname": socket.gethostname(),
            "run_as_root": os.geteuid() == 0,
            "www_root": args.www_root,
        },
        "host": {
            "disk": disk,
            "inode_pct_root": inode_pct,
            "ssl": collect_ssl([s["slug"] for s in sites]),
            "updates": collect_updates(),
        },
        "sites": sites,
        "logs": {
            **collect_web_logs(sites),
            "auth": collect_auth_log(),
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2))
    print(f"collect: wrote {out_path} "
          f"({len(sites)} site(s), auth={'yes' if data['logs']['auth'].get('available') else 'skipped'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
