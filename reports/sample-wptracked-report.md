# [ALERT] Varry LLC · WPTracked — Health Check

**Server:** `wp-prod-01`  
**Generated:** 2026-07-24T03:49:21.070858+00:00  
**Scope:** Server + WordPress  
**Sites:** site-one.example.com, site-two.example.com, site-three.example.com, site-four.example.com

## Summary
- **Verdict:** [ALERT] · 1 alert(s), 6 warning(s), 13 notice(s)
- [ALERT] **SSH** — root login via *password* from 203.0.113.66 (2x) — password root SSH is enabled; set PermitRootLogin prohibit-password + PasswordAuthentication no
- [WARN] **OS Updates** — 7 pending security update(s)
- [WARN] **WP Security** — wp-config.php mode 0o664 — tighten to 0640 or stricter (on 3 sites)
- [WARN] **WP Security** — wp-config.php mode 0o644 — tighten to 0640 or stricter
- [WARN] **SSH** — 3,139 failed/invalid SSH attempts (brute-force scanning) — no rate-limiting observed
- [INFO] **Plugins** — 6 plugin update(s) available across sites
- [INFO] **Notices** — 12 informational best-practice finding(s) (WP Security); see the sections below for details.

## Recommended Actions
1. [ALERT] **SSH** — root login via *password* from 203.0.113.66 (2x) — password root SSH is enabled; set PermitRootLogin prohibit-password + PasswordAuthentication no
1. [WARN] **OS Updates** — 7 pending security update(s)
1. [WARN] **WP Security** — wp-config.php mode 0o664 — tighten to 0640 or stricter (on 3 sites)
1. [WARN] **WP Security** — wp-config.php mode 0o644 — tighten to 0640 or stricter
1. [WARN] **SSH** — 3,139 failed/invalid SSH attempts (brute-force scanning) — no rate-limiting observed


## 1. Host Infrastructure

### Disk
| Filesystem | Size | Used | Avail | Use% | Mount |
|---|---|---|---|---|---|
| /dev/vda3 | 503G | 9,1G | 474G | 2% | / |
| /dev/vda2 | 975M | 261M | 664M | 29% | /boot |
| /dev/vda1 | 253M | 6,1M | 246M | 3% | /boot/efi |

Root inode usage: 1%.

### TLS Certificates
| Domain | Issuer | Expires | Days left |
|---|---|---|---|
| site-one.example.com | C = US, O = Google Trust Services, CN = WE1 | Oct  5 06:30:59 2026 GMT | 73 |
| site-two.example.com | C = US, O = Google Trust Services, CN = WE1 | Oct  5 06:30:59 2026 GMT | 73 |
| site-three.example.com | C = US, O = Google Trust Services, CN = WE1 | Oct  5 06:30:59 2026 GMT | 73 |
| site-four.example.com | C = US, O = Google Trust Services, CN = WE1 | Sep  5 03:08:15 2026 GMT | 42 |

### OS / Security Updates
- Applicable now: **7** (security: 7)
- ESM-only (Ubuntu Pro) security updates: 17
- Reboot required: no

## 2. WordPress Core Integrity
| Site | Version | Checksums |
|---|---|---|
| site-one.example.com | 7.0.2 | [OK] verified |
| site-two.example.com | 7.0.2 | [OK] verified |
| site-three.example.com | 7.0.2 | [OK] verified |
| site-four.example.com | 7.0.2 | [OK] verified |

## 3. WordPress Security Audit
| Site | Check | Status | Detail |
|---|---|---|---|
| site-one.example.com | wp-config-perms | [WARN] | wp-config.php mode 0o664 — tighten to 0640 or stricter |
| site-one.example.com | debug-display | [OK] | WP_DEBUG_DISPLAY is off |
| site-one.example.com | file-edit | [INFO] | DISALLOW_FILE_EDIT not set — dashboard code editor is active |
| site-one.example.com | table-prefix | [OK] | non-default table prefix (wpa1_) |
| site-one.example.com | admin-user | [OK] | 1 admin account(s), none named 'admin' |
| site-one.example.com | https | [OK] | site URL uses HTTPS |
| site-one.example.com | inactive-plugins | [INFO] | 2 inactive plugin(s) installed — remove if unused |
| site-one.example.com | readme-exposed | [INFO] | readme.html is present — discloses the WordPress version |
| site-two.example.com | wp-config-perms | [WARN] | wp-config.php mode 0o664 — tighten to 0640 or stricter |
| site-two.example.com | debug-display | [OK] | WP_DEBUG_DISPLAY is off |
| site-two.example.com | file-edit | [INFO] | DISALLOW_FILE_EDIT not set — dashboard code editor is active |
| site-two.example.com | table-prefix | [OK] | non-default table prefix (wpb2_) |
| site-two.example.com | admin-user | [OK] | 1 admin account(s), none named 'admin' |
| site-two.example.com | https | [OK] | site URL uses HTTPS |
| site-two.example.com | inactive-plugins | [INFO] | 2 inactive plugin(s) installed — remove if unused |
| site-two.example.com | readme-exposed | [INFO] | readme.html is present — discloses the WordPress version |
| site-three.example.com | wp-config-perms | [WARN] | wp-config.php mode 0o664 — tighten to 0640 or stricter |
| site-three.example.com | debug-display | [OK] | WP_DEBUG_DISPLAY is off |
| site-three.example.com | file-edit | [INFO] | DISALLOW_FILE_EDIT not set — dashboard code editor is active |
| site-three.example.com | table-prefix | [OK] | non-default table prefix (wpc3_) |
| site-three.example.com | admin-user | [OK] | 1 admin account(s), none named 'admin' |
| site-three.example.com | https | [OK] | site URL uses HTTPS |
| site-three.example.com | inactive-plugins | [INFO] | 2 inactive plugin(s) installed — remove if unused |
| site-three.example.com | readme-exposed | [INFO] | readme.html is present — discloses the WordPress version |
| site-four.example.com | wp-config-perms | [WARN] | wp-config.php mode 0o644 — tighten to 0640 or stricter |
| site-four.example.com | debug-display | [OK] | WP_DEBUG_DISPLAY is off |
| site-four.example.com | file-edit | [INFO] | DISALLOW_FILE_EDIT not set — dashboard code editor is active |
| site-four.example.com | table-prefix | [OK] | non-default table prefix (wpd4_) |
| site-four.example.com | admin-user | [OK] | 4 admin account(s), none named 'admin' |
| site-four.example.com | https | [OK] | site URL uses HTTPS |
| site-four.example.com | inactive-plugins | [INFO] | 6 inactive plugin(s) installed — remove if unused |
| site-four.example.com | readme-exposed | [INFO] | readme.html is present — discloses the WordPress version |

## 4. Plugins, Themes & Vulnerabilities

**Available updates:**
| Site | Type | Name | Installed | Latest |
|---|---|---|---|---|
| site-one.example.com | plugin | fluentform | 6.2.7 | 6.2.8 |
| site-one.example.com | plugin | mailpoet | 5.34.1 | 5.34.2 |
| site-two.example.com | plugin | fluentform | 6.2.7 | 6.2.8 |
| site-two.example.com | plugin | mailpoet | 5.34.1 | 5.34.2 |
| site-three.example.com | plugin | fluentform | 6.2.7 | 6.2.8 |
| site-three.example.com | plugin | mailpoet | 5.34.1 | 5.34.2 |

**Vulnerability scan** — 40 components vs wpvulnerability.net, CVEs cross-referenced with CISA KEV (1653 entries):
- [OK] **0 matching vulnerabilities**, **0 CISA KEV** matches — all installed versions are newer than every known-vulnerable version.
- No public listing (custom/premium — verify manually): `site-connector-mu`, `site-tools`, `blocks-builder`, `hello`, `mail-composer-pro`, `custom-toolkit`, `custom-toolkit-pro`, `slim-seo-pro`, `code-snippets-pro`, `sso-auto-login`, `storefront-theme`, `storefront-theme-child`
- Lookup did not complete for (re-run to confirm): `mail-composer`

## 5. Logs & Intrusion Scanning
- Web-server error log `site-one.example.com`: empty
- Web-server error log `site-two.example.com`: empty
- Web-server error log `site-three.example.com`: empty
- Web-server error log `site-four.example.com`: empty
- Access `site-one.example.com`: 496 reqs; 2xx=493, 4xx=2, 5xx=0
- Access `site-two.example.com`: 464 reqs; 2xx=461, 4xx=2, 5xx=0
- Access `site-three.example.com`: 491 reqs; 2xx=488, 4xx=2, 5xx=0
- Access `site-four.example.com`: 612 reqs; 2xx=568, 4xx=2, 5xx=0

### SSH auth.log
- Window: Jul 22 01:39:40 → Jul 24 05:49:15
- Invalid-user attempts: **3,081**; failed passwords: **58** (root: 23) — none successful.
- Accepted logins:
  - publickey for `root` from 198.51.100.10 ×157  (allowlisted)
  - password for `root` from 203.0.113.66 ×2
  - publickey for `deploy` from 198.51.100.11 ×1  (allowlisted)

---
_Generated by Varry LLC · WPTracked (https://wptracked.com) — automated, read-only health check._