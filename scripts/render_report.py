#!/usr/bin/env python3
"""
render_report.py — turn collected data + vuln scan into a branded report.

Produces three artifacts from the same source of truth:
  * Markdown (.md)  — plain, diff-friendly, e-mail text fallback
  * HTML (.html)    — Varry LLC branded, used as the e-mail body
  * PDF (.pdf)      — the branded attachment (rendered with WeasyPrint)

It also applies the health *rules* that decide the overall verdict
([ALERT] vs [HEALTHY]) and the per-item severity shown in the summary.
"""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import html
import json
import os
from pathlib import Path

# --------------------------------------------------------------------------- #
# Branding
# --------------------------------------------------------------------------- #
BRAND_COMPANY = os.environ.get("BRAND_COMPANY", "Varry LLC")
BRAND_PROJECT = os.environ.get("BRAND_PROJECT", "WPTracked")
REPO_URL = os.environ.get("WPT_REPO_URL", "https://github.com/varry-llc/WPTracked")
SITE_URL = os.environ.get("WPT_SITE_URL", "https://wptracked.com")
# WPTracked "spaghetti-western" palette (matches wptracked.com): rust-red
# primaries, leather/tan accent, parchment surfaces, ink text.
NAVY, TEAL, BLUE = "#7a2d23", "#c46b3b", "#963a2f"
GREEN, AMBER, RED, INK, MUTE = "#2b7a3b", "#b5701a", "#a12c2c", "#2c1f16", "#5e4735"

# Severity ordering
ALERT, WARN, INFO, OK = "alert", "warn", "info", "ok"


# --------------------------------------------------------------------------- #
# Rules engine
# --------------------------------------------------------------------------- #

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _allowlisted(ip: str) -> bool:
    allow = [p.strip() for p in os.environ.get("SSH_ALLOWLIST", "").split(",") if p.strip()]
    return any(ip == a or ip.startswith(a) for a in allow)


def evaluate(data: dict, vuln: dict) -> dict:
    """Return {status, items:[{severity,area,message}]} for the report."""
    items: list[dict] = []

    def add(sev, area, msg):
        items.append({"severity": sev, "area": area, "message": msg})

    host = data.get("host", {})

    # Disk
    for fs in host.get("disk", []):
        pct = fs.get("use_pct", 0)
        if pct >= _env_int("DISK_ALERT_PCT", 90):
            add(ALERT, "Disk", f"{fs['mount']} at {pct}% used")
        elif pct >= _env_int("DISK_WARN_PCT", 80):
            add(WARN, "Disk", f"{fs['mount']} at {pct}% used")

    # SSL
    for c in host.get("ssl", []):
        if c.get("error"):
            add(WARN, "SSL", f"{c['domain']}: could not read certificate ({c['error']})")
            continue
        dleft = c.get("days_left")
        if dleft is None:
            continue
        if dleft <= _env_int("SSL_ALERT_DAYS", 10):
            add(ALERT, "SSL", f"{c['domain']} expires in {dleft} days")
        elif dleft <= _env_int("SSL_WARN_DAYS", 21):
            add(WARN, "SSL", f"{c['domain']} expires in {dleft} days")

    # OS updates
    upd = host.get("updates", {})
    if upd.get("security"):
        add(WARN, "OS Updates", f"{upd['security']} pending security update(s)")
    if upd.get("reboot_required"):
        add(WARN, "OS Updates", "reboot required to finish applying updates")

    # WP core integrity
    for s in data.get("sites", []):
        if s.get("checksums_ok") is False:
            add(ALERT, "WP Core", f"{s['slug']}: core checksum verification FAILED")

    # WordPress security best-practices audit
    sev_map = {"alert": ALERT, "warn": WARN, "info": INFO}
    for s in data.get("sites", []):
        for chk in s.get("security", []):
            if chk.get("ok") or chk.get("severity") == "ok":
                continue
            add(sev_map.get(chk.get("severity"), INFO), "WP Security",
                f"{s['slug']}: {chk['detail']}")

    # Plugin updates (maintenance -> info)
    upd_count = sum(1 for s in data.get("sites", [])
                    for p in s.get("plugins", []) if p.get("update") == "available")
    if upd_count:
        add(INFO, "Plugins", f"{upd_count} plugin update(s) available across sites")

    # Vulnerabilities
    if vuln.get("kev_hits"):
        add(ALERT, "Vulnerabilities",
            f"{len(vuln['kev_hits'])} actively-exploited (CISA KEV) CVE(s): "
            + ", ".join(vuln["kev_hits"]))
    if vuln.get("findings"):
        add(ALERT, "Vulnerabilities",
            f"{len(vuln['findings'])} installed component(s) match known vulnerabilities")

    # Logs — 5xx
    for a in data.get("logs", {}).get("access", []):
        n = a.get("suspicious", {}).get("5xx", 0)
        if n:
            add(WARN, "Logs", f"{a['site']}: {n} HTTP 5xx response(s) in access log")

    # SSH auth
    auth = data.get("logs", {}).get("auth", {})
    if auth.get("available"):
        for rp in auth.get("root_password_logins", []):
            # Password-based root SSH is a hardening problem regardless of the
            # source IP, so this is always escalated.
            add(ALERT, "SSH", f"root login via *password* from {rp['ip']} "
                              f"({rp['count']}x) — password root SSH is enabled; "
                              f"set PermitRootLogin prohibit-password + "
                              f"PasswordAuthentication no")
        for acc in auth.get("accepted", []):
            if acc["method"] == "publickey" and not _allowlisted(acc["ip"]):
                add(WARN, "SSH", f"key login for {acc['user']} from non-allowlisted "
                                 f"{acc['ip']} ({acc['count']}x) — verify")
        attempts = auth.get("invalid_user", 0) + auth.get("failed_password", 0)
        if attempts >= 500:
            add(WARN, "SSH", f"{attempts:,} failed/invalid SSH attempts (brute-force "
                             f"scanning) — no rate-limiting observed")
    else:
        add(INFO, "SSH", "auth.log not inspected (run as root to include)")

    status = "ALERT" if any(i["severity"] == ALERT for i in items) else "HEALTHY"
    return {"status": status, "items": items}


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #

def render_markdown(data: dict, vuln: dict, verdict: dict) -> str:
    m = data["meta"]
    sites = data.get("sites", [])
    host = data.get("host", {})
    L: list[str] = []

    # --- Header ---------------------------------------------------------------
    L.append(f"# [{verdict['status']}] {BRAND_COMPANY} · {BRAND_PROJECT} — Health Check")
    L.append("")
    scope = "Server + WordPress" if m.get("mode") != "server" else "Server only"
    L.append(f"**Server:** `{m['server_label']}`  ")
    L.append(f"**Generated:** {m['generated_at']}  ")
    L.append(f"**Scope:** {scope}  ")
    if sites:
        L.append(f"**Sites:** {', '.join(s['slug'] for s in sites)}")
    L.append("")

    # --- Summary (prioritised findings) --------------------------------------
    L.append("## Summary")
    order = {ALERT: 0, WARN: 1, INFO: 2}
    icons = {ALERT: "🔴", WARN: "🟠", INFO: "🔵"}
    items = verdict["items"]
    counts = {s: sum(1 for i in items if i["severity"] == s) for s in (ALERT, WARN, INFO)}
    L.append(f"- **Verdict:** {'🔴 ALERT' if verdict['status']=='ALERT' else '🟢 HEALTHY'} "
             f"· {counts[ALERT]} alert(s), {counts[WARN]} warning(s), {counts[INFO]} notice(s)")
    sig = [i for i in items if i["severity"] in order]
    if sig:
        for i in sorted(sig, key=lambda x: order[x["severity"]]):
            L.append(f"- {icons[i['severity']]} **{i['area']}** — {i['message']}")
    else:
        L.append("- 🟢 All checks passed — no action required.")
    L.append("")

    # --- Recommendations (actionable, alerts + warnings) ----------------------
    todo = [i for i in items if i["severity"] in (ALERT, WARN)]
    if todo:
        L.append("## Recommended Actions")
        for i in sorted(todo, key=lambda x: order[x["severity"]]):
            tag = "ALERT" if i["severity"] == ALERT else "warn"
            L.append(f"1. **[{tag}] {i['area']}** — {i['message']}")
        L.append("")

    section = 0

    def h2(title: str) -> None:
        nonlocal section
        section += 1
        L.append(f"\n## {section}. {title}")

    # --- Host Infrastructure --------------------------------------------------
    h2("Host Infrastructure")
    if host.get("disk"):
        L.append("\n### Disk")
        L.append("| Filesystem | Size | Used | Avail | Use% | Mount |")
        L.append("|---|---|---|---|---|---|")
        for f in host["disk"]:
            L.append(f"| {f['filesystem']} | {f['size']} | {f['used']} | {f['avail']} | {f['use_pct']}% | {f['mount']} |")
        if host.get("inode_pct_root") is not None:
            L.append(f"\nRoot inode usage: {host['inode_pct_root']}%.")
    if host.get("ssl"):
        L.append("\n### TLS Certificates")
        L.append("| Domain | Issuer | Expires | Days left |")
        L.append("|---|---|---|---|")
        for c in host["ssl"]:
            if c.get("error"):
                L.append(f"| {c['domain']} | — | error | {c['error']} |")
            else:
                L.append(f"| {c['domain']} | {c.get('issuer','')} | {c.get('not_after','')} | {c.get('days_left','?')} |")
    upd = host.get("updates", {})
    if upd:
        L.append("\n### OS / Security Updates")
        L.append(f"- Applicable now: **{upd.get('updates', '?')}** (security: {upd.get('security', '?')})")
        if upd.get("esm"):
            L.append(f"- ESM-only (Ubuntu Pro) security updates: {upd['esm']}")
        L.append(f"- Reboot required: {'yes' if upd.get('reboot_required') else 'no'}")

    # --- WordPress Core Integrity --------------------------------------------
    if sites and any("checksums_ok" in s for s in sites):
        h2("WordPress Core Integrity")
        L.append("| Site | Version | Checksums |")
        L.append("|---|---|---|")
        for s in sites:
            ok = "✅ verified" if s.get("checksums_ok") else "❌ FAILED"
            L.append(f"| {s['slug']} | {s.get('wp_version','?')} | {ok} |")

    # --- WordPress Security Audit --------------------------------------------
    if sites and any(s.get("security") for s in sites):
        h2("WordPress Security Audit")
        sev_icon = {"alert": "🔴 ALERT", "warn": "🟠 WARN",
                    "info": "🔵 INFO", "ok": "✅ OK"}
        L.append("| Site | Check | Status | Detail |")
        L.append("|---|---|---|---|")
        for s in sites:
            for chk in s.get("security", []):
                icon = sev_icon.get(chk.get("severity"), "•")
                L.append(f"| {s['slug']} | {chk['id']} | {icon} | {chk['detail']} |")

    # --- Plugins, Themes & Vulnerabilities -----------------------------------
    if sites and any(("plugins" in s or "themes" in s) for s in sites):
        h2("Plugins, Themes & Vulnerabilities")
        updates = [(s['slug'], kind, p)
                   for s in sites
                   for kind, lst in (("plugin", s.get('plugins', [])),
                                     ("theme", s.get('themes', [])))
                   for p in lst if p.get('update') == 'available']
        if updates:
            L.append("\n**Available updates:**")
            L.append("| Site | Type | Name | Installed | Latest |")
            L.append("|---|---|---|---|---|")
            for slug, kind, p in updates:
                L.append(f"| {slug} | {kind} | {p['name']} | {p['version']} | {p.get('update_version','')} |")
        else:
            L.append("\nAll plugins and themes are up to date.")
        if data["meta"].get("checks", {}).get("CHECK_WP_VULN", True):
            L.append(f"\n**Vulnerability scan** — {vuln.get('components_scanned', 0)} components vs "
                     f"wpvulnerability.net, CVEs cross-referenced with CISA KEV "
                     f"({vuln.get('kev_catalog_size', 0)} entries):")
            if vuln.get("findings"):
                L.append(f"- ⚠️ **{len(vuln['findings'])} vulnerable component(s)** found:")
                for f in vuln["findings"]:
                    L.append(f"  - `{f['slug']}` {f['installed']} — {f.get('title','')} "
                             f"(CVEs: {', '.join(f['cves']) or 'n/a'})")
                if vuln.get("kev_hits"):
                    L.append(f"- 🔴 **CISA KEV (actively exploited):** {', '.join(vuln['kev_hits'])}")
            else:
                L.append("- ✅ **0 matching vulnerabilities**, **0 CISA KEV** matches — all installed "
                         "versions are newer than every known-vulnerable version.")
            not_listed = [c for c in vuln.get("coverage", [])
                          if not c["covered"] and c.get("reason") == "notlisted"]
            errored = [c for c in vuln.get("coverage", [])
                       if not c["covered"] and c.get("reason") == "error"]
            if not_listed:
                L.append("- No public listing (custom/premium — verify manually): "
                         + ", ".join(f"`{c['slug']}`" for c in not_listed))
            if errored:
                L.append("- Lookup did not complete for (re-run to confirm): "
                         + ", ".join(f"`{c['slug']}`" for c in errored))

    # --- Logs & Intrusion -----------------------------------------------------
    logs = data.get("logs", {})
    h2("Logs & Intrusion Scanning")
    for e in logs.get("ols_error_logs", []):
        state = "empty" if e["bytes"] == 0 else f"{e['bytes']} bytes"
        L.append(f"- Web-server error log `{e['site']}`: {state}")
    for a in logs.get("access", []):
        sc = a["status_counts"]
        L.append(f"- Access `{a['site']}`: {a['total']} reqs; "
                 f"2xx={sum(v for k,v in sc.items() if k.startswith('2'))}, "
                 f"4xx={sum(v for k,v in sc.items() if k.startswith('4'))}, "
                 f"5xx={a['suspicious'].get('5xx',0)}")
    auth = logs.get("auth", {})
    L.append("\n### SSH auth.log")
    if auth.get("available"):
        w = auth.get("window", {})
        L.append(f"- Window: {w.get('from','?')} → {w.get('to','?')}")
        L.append(f"- Invalid-user attempts: **{auth.get('invalid_user',0):,}**; "
                 f"failed passwords: **{auth.get('failed_password',0)}** "
                 f"(root: {auth.get('failed_root',0)}) — none successful.")
        if auth.get("accepted"):
            L.append("- Accepted logins:")
            for acc in auth["accepted"]:
                L.append(f"  - {acc['method']} for `{acc['user']}` from {acc['ip']} ×{acc['count']}"
                         + ("  (allowlisted)" if _allowlisted(acc['ip']) else ""))
    else:
        L.append(f"- Skipped: {auth.get('reason','not available')}")

    L.append("")
    L.append("---")
    L.append(f"_Generated by {BRAND_COMPANY} · {BRAND_PROJECT} ({SITE_URL}) — automated, read-only health check._")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# HTML (branded) — also used for the PDF
# --------------------------------------------------------------------------- #

def _logo_data_uri(variant: str = "") -> str:
    logo = os.environ.get("BRAND_LOGO", "assets/wptracked-logo.svg")
    if variant == "light":
        # Prefer a "*-light.svg" beside the configured logo (white wordmark for
        # the dark report header); fall back to the standard logo otherwise.
        cand = Path(logo)
        light = cand.with_name(cand.stem + "-light" + cand.suffix)
        if (Path(__file__).resolve().parent.parent / light).exists():
            logo = str(light)
    p = Path(logo)
    if not p.is_absolute():
        p = Path(__file__).resolve().parent.parent / logo
    if p.exists():
        b = base64.b64encode(p.read_bytes()).decode()
        mime = "image/svg+xml" if p.suffix == ".svg" else "image/png"
        return f"data:{mime};base64,{b}"
    return ""


def _md_inline(s: str) -> str:
    s = html.escape(s, quote=False)
    import re as _re
    s = _re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = _re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    return s


def render_html(md_text: str, verdict: dict, meta: dict) -> str:
    """Convert our own Markdown to a branded HTML document."""
    status = verdict["status"]
    pill = GREEN if status == "HEALTHY" else RED
    logo = _logo_data_uri("light")
    generated = meta.get("generated_at", "")
    server = meta.get("server_label", "")

    # Minimal but complete Markdown -> HTML (headings, tables, lists, hr, code).
    import re as _re
    body, in_tbl, in_ul, in_ol = [], False, False, False

    def _close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            body.append("</ul>"); in_ul = False
        if in_ol:
            body.append("</ol>"); in_ol = False

    for ln in md_text.splitlines():
        if ln.startswith("# "):
            continue  # rendered in the branded header instead
        if ln.startswith("**Server:**") or ln.startswith("**Generated:**"):
            continue  # shown in the branded meta bar instead
        if ln.startswith("|"):
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if all(_re.match(r"^:?-+:?$", c) for c in cells):
                continue
            if not in_tbl:
                _close_lists()
                body.append('<table>'); in_tbl = True; tag = "th"
            else:
                tag = "td"
            body.append("<tr>" + "".join(f"<{tag}>{_md_inline(c)}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_tbl:
            body.append("</table>"); in_tbl = False
        if _re.match(r"^\d+\. ", ln):
            if not in_ol:
                _close_lists(); body.append("<ol>"); in_ol = True
            item = _re.sub(r"^\d+\. ", "", ln)
            body.append(f"<li>{_md_inline(item)}</li>"); continue
        if ln.startswith("- ") or ln.startswith("  - "):
            if not in_ul:
                _close_lists(); body.append("<ul>"); in_ul = True
            indent = " style='margin-left:18px'" if ln.startswith("  - ") else ""
            body.append(f"<li{indent}>{_md_inline(ln.strip()[2:])}</li>"); continue
        _close_lists()
        if ln.startswith("### "):
            body.append(f"<h3>{_md_inline(ln[4:])}</h3>")
        elif ln.startswith("## "):
            body.append(f"<h2>{_md_inline(ln[3:])}</h2>")
        elif ln.startswith("---"):
            body.append("<hr>")
        elif ln.strip().startswith("_") and ln.strip().endswith("_"):
            body.append(f"<p class='foot'>{_md_inline(ln.strip().strip('_'))}</p>")
        elif ln.strip():
            body.append(f"<p>{_md_inline(ln)}</p>")
    if in_tbl:
        body.append("</table>")
    _close_lists()

    css = f"""
    :root {{ --navy:{NAVY}; --teal:{TEAL}; --blue:{BLUE}; --ink:{INK}; --mute:{MUTE}; }}
    * {{ box-sizing:border-box; }}
    body {{ font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
            color:var(--ink); margin:0; background:#efe6d2; font-size:13.5px; line-height:1.5; }}
    .wrap {{ max-width:860px; margin:0 auto; background:#fffdf7; }}
    .hdr {{ background:linear-gradient(135deg,{NAVY},#963a2f); color:#fff; padding:22px 28px;
            display:flex; align-items:center; justify-content:space-between; }}
    .hdr img {{ height:44px; }}
    .hdr .title {{ font-size:15px; font-weight:600; opacity:.9; }}
    .pill {{ display:inline-block; padding:6px 16px; border-radius:999px; font-weight:700;
             font-size:13px; letter-spacing:.5px; background:{pill}; color:#fff; }}
    .meta {{ padding:14px 28px; background:#e5d5b7; color:var(--mute); font-size:12.5px;
             border-bottom:1px solid #c4b596; }}
    .content {{ padding:8px 28px 28px; }}
    h2 {{ color:var(--navy); border-bottom:2px solid var(--teal); padding-bottom:4px;
          margin-top:26px; font-size:17px; }}
    h3 {{ color:var(--blue); margin:16px 0 6px; font-size:14px; }}
    table {{ border-collapse:collapse; width:100%; margin:8px 0 4px; font-size:12.5px; }}
    th, td {{ border:1px solid #d8c5a0; padding:6px 9px; text-align:left; }}
    th {{ background:{NAVY}; color:#fff; font-weight:600; }}
    tr:nth-child(even) td {{ background:#f6efe0; }}
    code {{ background:#efe6d2; padding:1px 5px; border-radius:4px; font-size:12px;
            font-family:'SFMono-Regular',Consolas,monospace; }}
    ul {{ margin:6px 0; padding-left:20px; }}
    li {{ margin:3px 0; }}
    hr {{ border:0; border-top:1px solid #d8c5a0; margin:18px 0; }}
    .foot {{ color:var(--mute); font-size:11.5px; }}
    .ftr {{ background:{NAVY}; color:#e5d5b7; padding:16px 28px; font-size:11.5px; text-align:center; }}
    .ftr a {{ color:{TEAL}; text-decoration:none; }}
    @page {{ size:A4; margin:14mm 12mm; }}
    """

    logo_html = f'<img src="{logo}" alt="{BRAND_COMPANY}">' if logo else \
        f'<div style="font-size:22px;font-weight:700">{BRAND_COMPANY}</div>'

    year = dt.datetime.now().year
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{BRAND_COMPANY} · {BRAND_PROJECT} — Health Check</title>
<style>{css}</style></head>
<body><div class="wrap">
  <div class="hdr">
    <div>{logo_html}<div class="title">{BRAND_PROJECT} — Server &amp; WordPress Health Check</div></div>
    <span class="pill">{status}</span>
  </div>
  <div class="meta"><strong>Server:</strong> {html.escape(server)} &nbsp;·&nbsp; <strong>Generated:</strong> {html.escape(generated)}</div>
  <div class="content">
    {''.join(body)}
  </div>
  <div class="ftr">© {year} {BRAND_COMPANY} · {BRAND_PROJECT} · automated, read-only health check ·
     <a href="{SITE_URL}">{SITE_URL.split('//')[-1]}</a> ·
     <a href="{REPO_URL}">{REPO_URL.split('github.com/')[-1]}</a></div>
</div></body></html>"""


def render_pdf(html_str: str, pdf_path: Path) -> bool:
    """Render HTML -> PDF with WeasyPrint. Returns False if unavailable."""
    try:
        from weasyprint import HTML  # imported lazily so md/html work without it
    except Exception as e:  # noqa: BLE001
        print(f"render_report: WeasyPrint unavailable, skipping PDF ({e})")
        return False
    HTML(string=html_str).write_pdf(str(pdf_path))
    return True


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="Render branded WP/server health report.")
    ap.add_argument("--data", default="out/data.json")
    ap.add_argument("--vuln", default="out/vuln.json")
    ap.add_argument("--out-dir", default="reports")
    ap.add_argument("--name", default=None, help="basename (default: wptracked-<date>)")
    args = ap.parse_args()

    data = json.loads(Path(args.data).read_text())
    vuln = json.loads(Path(args.vuln).read_text()) if Path(args.vuln).exists() else {}
    verdict = evaluate(data, vuln)

    name = args.name or f"wptracked-{dt.date.today().isoformat()}"
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    md = render_markdown(data, vuln, verdict)
    (out_dir / f"{name}.md").write_text(md)

    html_doc = render_html(md, verdict, data["meta"])
    (out_dir / f"{name}.html").write_text(html_doc)

    have_pdf = render_pdf(html_doc, out_dir / f"{name}.pdf")

    # Emit a tiny manifest so the orchestrator/sender knows what was produced.
    manifest = {
        "status": verdict["status"],
        "subject": f"[{verdict['status']}] {BRAND_COMPANY} · {BRAND_PROJECT} — "
                   f"Health Check ({data['meta']['server_label']}) "
                   f"{dt.date.today().isoformat()}",
        "md": str(out_dir / f"{name}.md"),
        "html": str(out_dir / f"{name}.html"),
        "pdf": str(out_dir / f"{name}.pdf") if have_pdf else None,
    }
    (out_dir / f"{name}.manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"render_report: {verdict['status']} -> {name}.md/.html"
          + ("/.pdf" if have_pdf else " (no pdf)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
