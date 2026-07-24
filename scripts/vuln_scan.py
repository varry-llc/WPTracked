#!/usr/bin/env python3
"""
vuln_scan.py — match installed plugins/themes against public vulnerability data.

Reads the inventory produced by collect.py, queries the free, no-auth
wpvulnerability.net feed for every installed component, decides whether the
*installed version* falls inside any known-vulnerable range, and finally
cross-references the resulting CVE IDs against the CISA KEV (Known Exploited
Vulnerabilities) catalog.

Data sources
------------
  wpvulnerability.net : https://www.wpvulnerability.net/{plugin|theme}/{slug}
                        (aggregates CVE + Patchstack + WPScan-style records)
  CISA KEV            : https://www.cisa.gov/.../known_exploited_vulnerabilities.json

Coverage note
-------------
  Custom / premium plugins that are not listed on wordpress.org have no public
  record and cannot be verified this way; they are reported as "no feed data".
  For authoritative, premium-inclusive scanning use a WPScan / Wordfence
  Intelligence / Patchstack API key.
"""
from __future__ import annotations
import argparse
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

UA = "Varry-WPMaintenance/1.0 (+https://github.com/varry-llc/WPMaintenance)"
FEED = "https://www.wpvulnerability.net/{kind}/{slug}"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


# --------------------------------------------------------------------------- #
# Version comparison — tolerant of WP-style versions like "1.0.0-beta-6"
# --------------------------------------------------------------------------- #

def _vkey(v: str):
    """Return a (numbers_tuple, prerelease_rank) sort key for a version."""
    v = str(v).strip().lower()
    prerelease = -1 if re.search(r"[-+ ](beta|alpha|rc|dev|pre|b|a)", v) else 0
    nums = re.findall(r"\d+", v.split("-")[0])
    return tuple(int(x) for x in nums) if nums else (0,), prerelease


def cmp_v(a: str, b: str) -> int:
    (na, pa), (nb, pb) = _vkey(a), _vkey(b)
    length = max(len(na), len(nb))
    na += (0,) * (length - len(na))
    nb += (0,) * (length - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    return (pa > pb) - (pa < pb)


def _satisfies(installed: str, op: str | None, ver: str | None) -> bool:
    if not ver or not op:
        return True
    c = cmp_v(installed, ver)
    return {"lt": c < 0, "le": c <= 0, "gt": c > 0,
            "ge": c >= 0, "eq": c == 0}.get(op, False)


def is_vulnerable(installed: str, vuln: dict) -> bool:
    """True when `installed` falls within this vuln entry's affected range."""
    o = vuln.get("operator", {}) or {}
    if not o.get("min_version") and not o.get("max_version"):
        return False  # no bounds -> don't assume vulnerable
    return (_satisfies(installed, o.get("min_operator"), o.get("min_version"))
            and _satisfies(installed, o.get("max_operator"), o.get("max_version")))


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def fetch_json(url: str, retries: int = 4, timeout: int = 30):
    """Return (status, data) where status is 'ok' | 'notlisted' | 'error'.

    'notlisted' means the component has no record in the DB (HTTP 404) — a
    definitive "no public data". 'error' means the lookup itself failed
    (network / 5xx after retries) and the result is simply unknown.
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "application/json"})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return "ok", json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "notlisted", None
            time.sleep(1.5 * (attempt + 1))
        except Exception:  # noqa: BLE001
            time.sleep(1.5 * (attempt + 1))
    return "error", None


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #

def inventory(data: dict) -> dict[tuple[str, str], dict]:
    """Build a slug -> {version, sites, status} map across all sites."""
    inv: dict[tuple[str, str], dict] = {}
    for site in data.get("sites", []):
        for kind, key in (("plugin", "plugins"), ("theme", "themes")):
            for comp in site.get(key, []):
                if not comp.get("version"):
                    continue
                k = (kind, comp["name"])
                entry = inv.setdefault(k, {"version": comp["version"],
                                           "status": comp.get("status"),
                                           "sites": []})
                entry["sites"].append(site["slug"])
    return inv


def scan(data: dict, delay: float = 0.8) -> dict:
    inv = inventory(data)
    findings, coverage, cves = [], [], set()
    for idx, ((kind, slug), meta) in enumerate(sorted(inv.items())):
        if idx:
            time.sleep(delay)  # be polite: the free feed rate-limits bursts
        status, feed = fetch_json(FEED.format(kind=kind, slug=slug))
        if status == "error":
            # Lookup itself failed (network / 5xx) — result unknown.
            coverage.append({"kind": kind, "slug": slug,
                             "version": meta["version"], "covered": False,
                             "reason": "error"})
            continue
        d = (feed or {}).get("data") or {}
        # The feed returns HTTP 200 with `vulnerability: null` to mean "no known
        # vulnerabilities". A record with no `name`/`link` (or a 404) means the
        # slug is not tracked at all — i.e. custom/premium, unverifiable here.
        vulns = d.get("vulnerability")
        if status == "notlisted" or (vulns is None and not d.get("name")):
            coverage.append({"kind": kind, "slug": slug,
                             "version": meta["version"], "covered": False,
                             "reason": "notlisted"})
            continue
        vulns = vulns or []  # known component, zero recorded vulnerabilities
        highest_fixed = None
        for v in vulns:
            mv = (v.get("operator") or {}).get("max_version")
            if mv and (highest_fixed is None or cmp_v(mv, highest_fixed) > 0):
                highest_fixed = mv
        coverage.append({"kind": kind, "slug": slug, "version": meta["version"],
                         "covered": True, "known_vulns": len(vulns),
                         "highest_fixed": highest_fixed})
        for v in vulns:
            if not is_vulnerable(meta["version"], v):
                continue
            vuln_cves = [s["id"] for s in (v.get("source") or [])
                         if str(s.get("id", "")).startswith("CVE-")]
            cves.update(vuln_cves)
            findings.append({
                "kind": kind, "slug": slug, "installed": meta["version"],
                "status": meta["status"], "sites": sorted(set(meta["sites"])),
                "title": v.get("name"),
                "fixed_in": (v.get("operator") or {}).get("max_version"),
                "unfixed": (v.get("operator") or {}).get("unfixed") == "1",
                "cves": vuln_cves,
                "refs": [s.get("link") for s in (v.get("source") or []) if s.get("link")][:3],
            })

    _, kev = fetch_json(KEV_URL)
    kev_ids = {x["cveID"] for x in kev.get("vulnerabilities", [])} if kev else set()
    kev_hits = sorted(cves & kev_ids)

    return {
        "findings": findings,
        "cves": sorted(cves),
        "kev_hits": kev_hits,
        "kev_catalog_size": len(kev_ids),
        "coverage": coverage,
        "components_scanned": len(inv),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Vulnerability + KEV scan of WP inventory.")
    ap.add_argument("--data", default="out/data.json", help="collect.py output")
    ap.add_argument("--out", default="out/vuln.json", help="scan output path")
    ap.add_argument("--delay", type=float, default=0.8,
                    help="seconds between feed requests (rate-limit courtesy)")
    args = ap.parse_args()

    data = json.loads(Path(args.data).read_text())
    result = scan(data, delay=args.delay)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"vuln_scan: {result['components_scanned']} components, "
          f"{len(result['findings'])} matches, "
          f"{len(result['cves'])} CVEs, "
          f"{len(result['kev_hits'])} KEV hit(s) -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
