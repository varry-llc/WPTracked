# The report: contents, verdict rules & branding

## Artifacts

`render_report.py` produces four files per run in `reports/` (basename
`wp-health-<date>` by default):

| File | Use |
|---|---|
| `*.md` | Plain Markdown — diff-friendly and the e-mail **text** part |
| `*.html` | Varry LLC–branded HTML — the e-mail **body** |
| `*.pdf` | Branded PDF — the e-mail **attachment** |
| `*.manifest.json` | `{status, subject, md, html, pdf}` — consumed by `send_report.py` |

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
| 🟠 warn | Disk ≥ `DISK_WARN_PCT`, cert within `SSL_WARN_DAYS`, pending security updates, reboot required, key login from a non-allowlisted IP, ≥ 500 failed/invalid SSH attempts |
| 🔵 info | Plugin updates available (maintenance), auth.log skipped |

Everything that fires is listed, most-severe first, in the **Summary** block.

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
- Logos: [`assets/varry-logo.svg`](../assets/varry-logo.svg) (dark text, for
  light backgrounds) and [`assets/varry-logo-light.svg`](../assets/varry-logo-light.svg)
  (white text, used in the dark report header).
- Override any of `BRAND_COMPANY`, `BRAND_PROJECT`, `BRAND_LOGO` via the config
  to re-brand for another client.
