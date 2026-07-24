#!/usr/bin/env python3
"""
Unit tests for WPTracked — run with:  python3 -m unittest discover -s tests

These are hermetic: no network, no live server, no real e-mail. They cover the
security-critical behaviours (verdict correctness, config toggles, transport
selection, fail-safe delivery, no-secret-leak).
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import collect  # noqa: E402
import render_report as rr  # noqa: E402
import send_report as sr  # noqa: E402


def base_data() -> dict:
    return {
        "meta": {"generated_at": "2026-07-24T00:00:00+00:00",
                 "server_label": "host", "hostname": "host", "run_as_root": True,
                 "www_root": "/var/www", "mode": "server+wp",
                 "checks": {"CHECK_WP_VULN": True}},
        "host": {"disk": [{"filesystem": "/dev/sda1", "size": "1G", "used": "1G",
                           "avail": "0", "use_pct": 95, "mount": "/"}],
                 "inode_pct_root": 5, "ssl": [], "updates": {}},
        "sites": [],
        "logs": {"ols_error_logs": [], "access": [], "auth": {"available": False,
                 "reason": "test"}},
    }


class ConfigToggles(unittest.TestCase):
    def tearDown(self):
        for k in ("CHECK_X", "WPT_MODE"):
            os.environ.pop(k, None)

    def test_flag_default_on(self):
        self.assertTrue(collect.flag("CHECK_X"))

    def test_flag_off_values(self):
        for v in ("0", "false", "no", "off", ""):
            os.environ["CHECK_X"] = v
            self.assertFalse(collect.flag("CHECK_X"), v)

    def test_mode(self):
        os.environ["WPT_MODE"] = "server"
        self.assertFalse(collect.wp_enabled())
        os.environ["WPT_MODE"] = "server+wp"
        self.assertTrue(collect.wp_enabled())


class Verdict(unittest.TestCase):
    def test_disk_alert(self):
        v = rr.evaluate(base_data(), {})
        self.assertEqual(v["status"], "ALERT")  # disk 95% >= alert threshold

    def test_healthy(self):
        d = base_data()
        d["host"]["disk"][0]["use_pct"] = 3
        v = rr.evaluate(d, {})
        self.assertEqual(v["status"], "HEALTHY")

    def test_root_password_login_is_alert(self):
        d = base_data()
        d["host"]["disk"][0]["use_pct"] = 3
        d["logs"]["auth"] = {"available": True, "root_password_logins":
                             [{"ip": "1.2.3.4", "count": 1}], "accepted": []}
        v = rr.evaluate(d, {})
        self.assertEqual(v["status"], "ALERT")

    def test_wp_security_alert_bubbles_up(self):
        d = base_data()
        d["host"]["disk"][0]["use_pct"] = 3
        d["sites"] = [{"slug": "s1", "security": [
            {"id": "wp-config-perms", "ok": False, "severity": "alert",
             "detail": "world-writable"}]}]
        v = rr.evaluate(d, {})
        self.assertEqual(v["status"], "ALERT")


class ServerOnlyReport(unittest.TestCase):
    def test_no_wp_sections_when_no_sites(self):
        d = base_data()
        d["meta"]["mode"] = "server"
        md = rr.render_markdown(d, {}, rr.evaluate(d, {}))
        self.assertIn("Host Infrastructure", md)
        self.assertNotIn("WordPress Core Integrity", md)
        self.assertIn("Server only", md)


class Transports(unittest.TestCase):
    def _manifest(self, tmp: Path) -> str:
        (tmp / "r.md").write_text("# report\nbody")
        (tmp / "r.html").write_text("<h1>report</h1>")
        mf = {"subject": "[HEALTHY] test", "md": str(tmp / "r.md"),
              "html": str(tmp / "r.html"), "pdf": None}
        p = tmp / "r.manifest.json"
        p.write_text(json.dumps(mf))
        return str(p)

    def setUp(self):
        os.environ["MAIL_FROM"] = "WPTracked <a@example.com>"
        os.environ["MAIL_TO"] = "b@example.com"

    def tearDown(self):
        for k in ("MAIL_FROM", "MAIL_TO", "EMAILIT_API_KEY", "SMTP_HOST",
                  "SENDGRID_API_KEY", "RESEND_API_KEY", "MAILGUN_API_KEY"):
            os.environ.pop(k, None)

    def test_missing_from_fails_validation(self):
        os.environ.pop("MAIL_FROM")
        with tempfile.TemporaryDirectory() as t:
            msg = sr.Message(self._manifest(Path(t)))
            self.assertTrue(msg.validate_common())

    def test_emailit_missing_key_fails(self):
        with tempfile.TemporaryDirectory() as t:
            msg = sr.Message(self._manifest(Path(t)))
            ok, _ = sr.send_emailit(msg, dry=False)
            self.assertFalse(ok)

    def test_dry_run_never_sends(self):
        os.environ["EMAILIT_API_KEY"] = "secret-key-value"
        with tempfile.TemporaryDirectory() as t:
            msg = sr.Message(self._manifest(Path(t)))
            for fn in (sr.send_emailit, sr.send_smtp, sr.send_sendgrid,
                       sr.send_resend, sr.send_mailgun):
                # provide the minimum config so dry-run reaches the "would send"
                os.environ["SMTP_HOST"] = "smtp.example.com"
                os.environ["SENDGRID_API_KEY"] = "x"
                os.environ["RESEND_API_KEY"] = "x"
                os.environ["MAILGUN_API_KEY"] = "x"
                os.environ["MAILGUN_DOMAIN"] = "d"
                ok, info = fn(msg, dry=True)
                self.assertTrue(ok)
                self.assertNotIn("secret-key-value", info)  # never leak the key


if __name__ == "__main__":
    unittest.main()
