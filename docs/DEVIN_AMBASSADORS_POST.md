# Devin Ambassadors — demo post

*Copy/paste into the Devin Ambassadors Slack. Trim to taste; the repo link and
the "read-only" framing are the important bits.*

---

🛡️ **WPTracked — a read-only server + WordPress security auditor that runs on your own box via a Devin outpost**

I built **WPTracked** (by Varry LLC · https://wptracked.com) to replace the
"SSH in and eyeball everything once a quarter" ritual with a repeatable,
branded audit that anyone on the team can run.

**The problem it solves:** WordPress/VPS health drifts silently — a cert quietly
approaching expiry, a plugin one version behind a CVE, `wp-config.php` left
group-writable, password root SSH still enabled, brute-force noise nobody's
watching. WPTracked checks all of it on a schedule and e-mails a clear
`[HEALTHY]` / `[ALERT]` report.

**What it audits (all toggleable, `server` or `server+wordpress` scope):**
• Host: disk/inodes, TLS expiry, pending OS/security updates, reboot flag
• WordPress core: `wp core verify-checksums` (tamper detection)
• Plugins/themes: per-site inventory + available updates
• Vulnerabilities: wpvulnerability.net (CVE/Patchstack) cross-referenced with the **CISA KEV** catalog
• WP security best-practices: file perms, `WP_DEBUG_DISPLAY`, `DISALLOW_FILE_EDIT`, default table prefix, predictable `admin`, HTTPS, dormant plugins, version disclosure
• Logs: web-server errors, access-log probes (wp-login/xmlrpc/user-enum/.env), and SSH `auth.log` brute-force + successful-login analysis

**The Devin angle:** it runs *on the target server* through a **Devin outpost** —
so WP-CLI, the real logs, and the certs are all evaluated against production —
and you can drive recurring runs with a **Devin Automation** that keeps the mail
credential in Devin's secret store instead of on the host. I leaned on the
native outpost/automation flow rather than reinventing any of it.

**Delivery is provider-agnostic:** `MAIL_TRANSPORT` = EmailIt / SMTP / SendGrid /
Mailgun / Resend. Branded HTML e-mail body + a PDF attachment.

**Security posture (the whole point):** it is **strictly read-only** — it never
updates, edits, or reconfigures anything. An uninspectable check is reported as
*incomplete*, never as "clean". Credentials are never logged or put on a command
line; runs are locked, timed out, and idempotent.

**Live demo result:** on a 3-site OpenLiteSpeed host it returned `[ALERT]` —
correctly flagging password-root SSH + unthrottled brute-force, while confirming
cores intact and **0 known vulns / 0 CISA KEV**. Two maintenance updates
(Fluent Forms, MailPoet) surfaced as info, not alerts.

**Roadmap (not enabled today):** an opt-in mode to perform *approved* updates
with pre-update backups, staged rollout, post-update health checks, rollback,
and an e-mailed update summary.

👉 Repo: https://github.com/varry-llc/WPTracked
👉 Product: https://wptracked.com

Happy to walk anyone through the outpost setup. 🤠
