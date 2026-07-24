# The report: contents, verdict rules & branding

## Artifacts

`render_report.py` produces four files per run in `reports/` (basename
`wptracked-<date>` by default):

| File | Use |
|---|---|
| `*.md` | Plain Markdown — diff-friendly and the e-mail **text** part |
| `*.html` | WPTracked-branded HTML — the e-mail **body** |
| `*.pdf` | Branded PDF — the e-mail **attachment** |
| `*.manifest.json` | `{status, subject, md, html, pdf}` — consumed by `send_report.py` |

## Report sections (logical grouping)

1. **Header** — verdict, server, scope (`Server only` / `Server + WordPress`), sites.
2. **Summary** — one-line verdict + counts, then every finding, most-severe first.
3. **Recommended Actions** — the alert/warning findings as an ordered to-do list.
4. **Host Infrastructure** — disk/inodes, TLS certificates, OS/security updates + reboot.
5. **WordPress Core Integrity** — per-site version + `verify-checksums`.
6. **WordPress Security Audit** — per-site best-practice table (see below).
7. **Plugins, Themes & Vulnerabilities** — available updates + vuln/CVE/KEV results + coverage caveats.
8. **Logs & Intrusion Scanning** — web-server error/access logs + SSH `auth.log`.

WordPress sections are omitted entirely in `WPT_MODE=server`. A disabled check
(`CHECK_*=0`) is left out rather than shown as passing.

## Verdict rules

The subject line is `[ALERT]` if **any** of the following is true, else
`[HEALTHY]`:

| Severity | Condition |
|---|---|
| 🔴 ALERT | `wp core verify-checksums` fails on any site |
| 🔴 ALERT | An installed plugin/theme matches a known vulnerability |
| 🔴 ALERT | A matched CVE is in the **CISA KEV** catalog (actively exploited) |
| 🔴 ALERT | Any filesystem ≥ `DISK_ALERT_PCT` (default 90%) |
| 🔴 ALERT | A TLS cert expires within `SSL_ALERT_DAYS` (default 10) |
| 🔴 ALERT | HTTP 5xx responses present in an access log |
| 🔴 ALERT | Password-based **root** SSH login observed (hardening) |
| 🔴 ALERT | A WP security check flagged as `alert` (e.g. world-writable `wp-config.php`) |
| 🟠 warn | Disk ≥ `DISK_WARN_PCT`, cert within `SSL_WARN_DAYS`, pending security updates, reboot required, key login from a non-allowlisted IP, ≥ 500 failed/invalid SSH attempts, WP security `warn` items |
| 🔵 info | Plugin updates available (maintenance), WP security `info` items, auth.log skipped |

Everything that fires is listed, most-severe first, in the **Summary** block and
(for alerts/warnings) again as an ordered **Recommended Actions** list.

## The WordPress security audit

Read-only best-practice checks per site (all `info`/`warn` unless noted):

| Check | Flags when |
|---|---|
| `wp-config-perms` | `wp-config.php` group/world readable/writable (**alert** if world-writable) |
| `debug-display` | `WP_DEBUG_DISPLAY` on (leaks errors to visitors) |
| `file-edit` | `DISALLOW_FILE_EDIT` not set (dashboard code editor active) |
| `table-prefix` | default `wp_` prefix in use |
| `admin-user` | an administrator literally named `admin` exists |
| `https` | site URL is not HTTPS |
| `inactive-plugins` | inactive plugins installed (dormant attack surface) |
| `readme-exposed` | `readme.html` present (discloses WP version) |

Secrets (salts, DB password, API keys) are **never** read or shown. A value the
tool cannot inspect is simply omitted — never assumed safe.

## The vulnerability check

- Each installed component is looked up on
  `https://www.wpvulnerability.net/{plugin|theme}/{slug}`.
- A component is flagged **only** when its *installed version* falls within a
  known-vulnerable range (`min`/`max` operators), i.e. it isn't already patched.
- Matched CVE IDs are intersected with the CISA KEV catalog.
- Coverage is reported honestly:
  - **No public listing** — custom/premium plugins not on wordpress.org
    (verify manually / with a commercial feed).
  - **Lookup did not complete** — a transient feed error; re-run to confirm.
- A failed lookup is **never** presented as "no vulnerabilities".

For authoritative, premium-inclusive scanning, add a WPScan / Wordfence
Intelligence / Patchstack API key (future enhancement).

## Branding

- Colours: navy `#12224A`, teal `#2DD4BF`, accent blue `#1E6FB8`; status green
  `#1E9E5A` / red `#C8102E`.
- Logos: [`assets/wptracked-logo.svg`](../assets/wptracked-logo.svg) (dark text,
  for light backgrounds) and
  [`assets/wptracked-logo-light.svg`](../assets/wptracked-logo-light.svg)
  (white text, used in the dark report header).
- Override any of `BRAND_COMPANY`, `BRAND_PROJECT`, `BRAND_LOGO`, `WPT_REPO_URL`,
  `WPT_SITE_URL` via the config to re-brand for another client.
