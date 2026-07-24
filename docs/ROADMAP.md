# Roadmap — approved automated updates (future, not enabled)

WPTracked is intentionally **read-only** today. A future, **opt-in** version will
add *approved* remediation. It is documented here so the design intent is clear;
none of it is implemented, and the audit will never mutate a site until it is.

Planned, behind an explicit opt-in and per-run approval:

- **Update allow/deny lists** — choose exactly which plugins/themes/core may be
  updated automatically; everything else stays report-only.
- **Pre-update backup** — database + files snapshot before any change, with a
  verified restore path.
- **Staged rollout** — update one site, health-check it, then proceed; halt the
  batch on regression.
- **Post-update health verification** — re-run the relevant checks (HTTP status,
  checksums, error logs) and roll back automatically on failure.
- **Rollback** — restore the pre-update snapshot on any failed verification.
- **Maintenance windows** — only act within a configured window.
- **E-mailed update summary** — what changed, before/after versions, and the
  post-update verdict, in the same branded format.

Guardrails that will remain non-negotiable:

- Nothing runs without an explicit opt-in flag **and** a per-run approval.
- No SSH/firewall/OS-level changes — application updates only.
- Every action is logged; secrets are never logged or exposed.
- If any safety precondition (backup, window, verification) can't be met, the
  update is **skipped** and reported — never forced.
