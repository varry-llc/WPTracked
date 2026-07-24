#!/usr/bin/env python3
"""
send_report.py — deliver the branded health report by e-mail.

Provider-agnostic: the transport is chosen with MAIL_TRANSPORT and the report
is delivered identically regardless of provider. Supported transports:

  emailit   EmailIt HTTP API      (https://emailit.com/docs)
  smtp      any SMTP server       (Gmail, SES, Postfix, Fastmail, …)
  sendgrid  SendGrid v3 HTTP API
  mailgun   Mailgun HTTP API
  resend    Resend HTTP API
  none      never send (generate the report only)

The e-mail body is the branded HTML report; the branded PDF is attached (with a
Markdown/.txt fallback if WeasyPrint was unavailable). The Markdown is always
used as the plain-text alternative.

Security / fail-safe design
---------------------------
* Credentials are read from the environment only and are NEVER printed, logged,
  or placed on a command line.
* Provider configuration is validated before any network call; a missing key
  or address fails loudly with a non-zero exit — delivery is never silently
  skipped or falsely reported as successful.
* HTTP transports use bounded retries with backoff and hard timeouts.
* An Idempotency-Key is sent where the provider supports it, so a retried run
  does not duplicate the e-mail.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import smtplib
import sys
import time
import urllib.error
import urllib.request
import uuid
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from pathlib import Path

HTTP_TIMEOUT = int(os.environ.get("MAIL_HTTP_TIMEOUT", "60"))
HTTP_RETRIES = int(os.environ.get("MAIL_HTTP_RETRIES", "3"))


# --------------------------------------------------------------------------- #
# Message assembly (transport-independent)
# --------------------------------------------------------------------------- #

class Message:
    """The rendered e-mail, ready for any transport."""

    def __init__(self, manifest_path: str) -> None:
        mf = json.loads(Path(manifest_path).read_text())
        self.subject: str = mf["subject"]
        self.html: str = Path(mf["html"]).read_text()
        self.text: str = Path(mf["md"]).read_text()
        self.sender: str = os.environ.get("MAIL_FROM", "").strip()
        self.recipients: list[str] = [
            a.strip() for a in os.environ.get("MAIL_TO", "").split(",") if a.strip()
        ]
        self.reply_to: str = os.environ.get("MAIL_REPLY_TO", "").strip()

        # Prefer the branded PDF; fall back to the Markdown as .txt.
        stem = Path(mf["md"]).stem
        if mf.get("pdf") and Path(mf["pdf"]).exists():
            self.attachment_name = f"{stem}.pdf"
            self.attachment_bytes = Path(mf["pdf"]).read_bytes()
            self.attachment_type = "application/pdf"
        else:
            self.attachment_name = f"{stem}.txt"
            self.attachment_bytes = self.text.encode("utf-8")
            self.attachment_type = "text/plain"

        # A stable idempotency key for this render (survives retries within a run).
        self.idempotency_key = "wptracked-" + uuid.uuid4().hex

    def attachment_b64(self) -> str:
        return base64.b64encode(self.attachment_bytes).decode("ascii")

    def validate_common(self) -> list[str]:
        errs = []
        if not self.sender or "@" not in parseaddr(self.sender)[1]:
            errs.append("MAIL_FROM is missing or not a valid address")
        if not self.recipients:
            errs.append("MAIL_TO is empty")
        return errs


# --------------------------------------------------------------------------- #
# HTTP helper
# --------------------------------------------------------------------------- #

def _http_post(url: str, data: bytes, headers: dict[str, str]) -> tuple[int, str]:
    """POST with bounded retries + backoff. Returns (status, body). Never raises."""
    last = (0, "")
    for attempt in range(HTTP_RETRIES):
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            last = (e.code, body)
            # 4xx (except 429) are permanent — do not keep retrying.
            if 400 <= e.code < 500 and e.code != 429:
                return last
        except Exception as e:  # noqa: BLE001 — network/DNS/timeout: retry
            last = (0, str(e))
        if attempt < HTTP_RETRIES - 1:
            time.sleep(1.5 * (attempt + 1))
    return last


def _ok(status: int) -> bool:
    return 200 <= status < 300


# --------------------------------------------------------------------------- #
# Transports — each returns (ok, human_readable_status)
# --------------------------------------------------------------------------- #

def send_emailit(msg: Message, dry: bool) -> tuple[bool, str]:
    key = os.environ.get("EMAILIT_API_KEY", "").strip()
    if not key:
        return False, "EMAILIT_API_KEY is not set"
    if dry:
        return True, "[dry-run] emailit"
    payload = {
        "from": msg.sender, "to": ",".join(msg.recipients),
        "subject": msg.subject, "text": msg.text, "html": msg.html,
        "attachments": [{"filename": msg.attachment_name,
                         "content": msg.attachment_b64(),
                         "content_type": msg.attachment_type}],
    }
    if msg.reply_to:
        payload["reply_to"] = msg.reply_to
    status, body = _http_post(
        "https://api.emailit.com/v2/emails",
        json.dumps(payload).encode(),
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
         "Accept": "application/json", "Idempotency-Key": msg.idempotency_key})
    return _ok(status), f"emailit HTTP {status}: {body[:200]}"


def send_sendgrid(msg: Message, dry: bool) -> tuple[bool, str]:
    key = os.environ.get("SENDGRID_API_KEY", "").strip()
    if not key:
        return False, "SENDGRID_API_KEY is not set"
    if dry:
        return True, "[dry-run] sendgrid"
    from_name, from_addr = parseaddr(msg.sender)
    payload = {
        "personalizations": [{"to": [{"email": a} for a in msg.recipients]}],
        "from": {"email": from_addr, "name": from_name or None},
        "subject": msg.subject,
        "content": [{"type": "text/plain", "value": msg.text},
                    {"type": "text/html", "value": msg.html}],
        "attachments": [{"filename": msg.attachment_name,
                         "content": msg.attachment_b64(),
                         "type": msg.attachment_type,
                         "disposition": "attachment"}],
    }
    if msg.reply_to:
        payload["reply_to"] = {"email": parseaddr(msg.reply_to)[1]}
    status, body = _http_post(
        "https://api.sendgrid.com/v3/mail/send",
        json.dumps(payload).encode(),
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    return _ok(status), f"sendgrid HTTP {status}: {body[:200]}"


def send_resend(msg: Message, dry: bool) -> tuple[bool, str]:
    key = os.environ.get("RESEND_API_KEY", "").strip()
    if not key:
        return False, "RESEND_API_KEY is not set"
    if dry:
        return True, "[dry-run] resend"
    payload = {
        "from": msg.sender, "to": msg.recipients, "subject": msg.subject,
        "text": msg.text, "html": msg.html,
        "attachments": [{"filename": msg.attachment_name,
                         "content": msg.attachment_b64()}],
    }
    if msg.reply_to:
        payload["reply_to"] = msg.reply_to
    status, body = _http_post(
        "https://api.resend.com/emails",
        json.dumps(payload).encode(),
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
         "Idempotency-Key": msg.idempotency_key})
    return _ok(status), f"resend HTTP {status}: {body[:200]}"


def send_mailgun(msg: Message, dry: bool) -> tuple[bool, str]:
    key = os.environ.get("MAILGUN_API_KEY", "").strip()
    domain = os.environ.get("MAILGUN_DOMAIN", "").strip()
    base = os.environ.get("MAILGUN_BASE", "https://api.mailgun.net").rstrip("/")
    if not key or not domain:
        return False, "MAILGUN_API_KEY and MAILGUN_DOMAIN are required"
    if dry:
        return True, "[dry-run] mailgun"
    # multipart/form-data with the PDF as a file part.
    boundary = "----wptracked" + uuid.uuid4().hex
    fields = [("from", msg.sender), ("subject", msg.subject),
              ("text", msg.text), ("html", msg.html)]
    fields += [("to", a) for a in msg.recipients]
    if msg.reply_to:
        fields.append(("h:Reply-To", msg.reply_to))
    parts = []
    for name, val in fields:
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; "
                     f'name="{name}"\r\n\r\n{val}\r\n'.encode())
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; "
        f'filename="{msg.attachment_name}"\r\n'
        f"Content-Type: {msg.attachment_type}\r\n\r\n".encode()
        + msg.attachment_bytes + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    data = b"".join(parts)
    auth = base64.b64encode(f"api:{key}".encode()).decode()
    status, body = _http_post(
        f"{base}/v3/{domain}/messages", data,
        {"Authorization": f"Basic {auth}",
         "Content-Type": f"multipart/form-data; boundary={boundary}"})
    return _ok(status), f"mailgun HTTP {status}: {body[:200]}"


def send_smtp(msg: Message, dry: bool) -> tuple[bool, str]:
    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        return False, "SMTP_HOST is not set"
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    security = os.environ.get("SMTP_SECURITY", "starttls").strip().lower()
    if dry:
        return True, f"[dry-run] smtp {host}:{port} ({security})"

    em = EmailMessage()
    name, addr = parseaddr(msg.sender)
    em["From"] = formataddr((name, addr))
    em["To"] = ", ".join(msg.recipients)
    em["Subject"] = msg.subject
    if msg.reply_to:
        em["Reply-To"] = msg.reply_to
    em.set_content(msg.text)
    em.add_alternative(msg.html, subtype="html")
    maintype, subtype = msg.attachment_type.split("/", 1)
    em.add_attachment(msg.attachment_bytes, maintype=maintype, subtype=subtype,
                      filename=msg.attachment_name)
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=HTTP_TIMEOUT)
        else:
            server = smtplib.SMTP(host, port, timeout=HTTP_TIMEOUT)
        with server:
            server.ehlo()
            if security == "starttls":
                server.starttls()
                server.ehlo()
            if user:
                server.login(user, password)
            server.send_message(em)
    except Exception as e:  # noqa: BLE001
        return False, f"smtp error: {type(e).__name__}: {e}"
    return True, f"smtp accepted via {host}:{port}"


TRANSPORTS = {
    "emailit": send_emailit,
    "smtp": send_smtp,
    "sendgrid": send_sendgrid,
    "mailgun": send_mailgun,
    "resend": send_resend,
}


def main() -> int:
    ap = argparse.ArgumentParser(description="Send the health report.")
    ap.add_argument("--manifest", required=True, help="render_report manifest.json")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate + build payload but do not send")
    args = ap.parse_args()

    transport = os.environ.get("MAIL_TRANSPORT", "emailit").strip().lower()
    if transport in ("none", ""):
        print("MAIL_TRANSPORT=none — report generated, delivery skipped.")
        return 0
    if transport not in TRANSPORTS:
        print(f"ERROR: unknown MAIL_TRANSPORT '{transport}' "
              f"(choose: {', '.join(TRANSPORTS)}, none)", file=sys.stderr)
        return 2

    msg = Message(args.manifest)
    errs = msg.validate_common()
    if errs:
        print("ERROR: mail configuration invalid:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 2

    ok, info = TRANSPORTS[transport](msg, args.dry_run)
    print(f"[{transport}] {info}")
    if not ok:
        print("ERROR: report was NOT delivered.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
