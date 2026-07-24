#!/usr/bin/env python3
"""
send_report.py — deliver the branded health report by e-mail via EmailIt.

Reads the manifest written by render_report.py (subject + HTML body + PDF
attachment) and POSTs it to the EmailIt v2 API
(https://emailit.com/docs/api-reference/emails/send).

The e-mail body is the branded HTML report; the PDF is attached so the
recipient always has a clean, printable, Varry LLC-branded copy. If no PDF was
produced (WeasyPrint unavailable) it falls back to attaching the Markdown.

Environment
-----------
  EMAILIT_API_KEY   Bearer token (REQUIRED).
  MAIL_FROM         Sender on an EmailIt-verified domain.
  MAIL_TO           Comma-separated recipients.
  MAIL_REPLY_TO     Optional reply-to address.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

API = "https://api.emailit.com/v2/emails"


def b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser(description="Send report via EmailIt.")
    ap.add_argument("--manifest", required=True, help="render_report manifest.json")
    ap.add_argument("--dry-run", action="store_true", help="build payload but do not send")
    args = ap.parse_args()

    key = os.environ.get("EMAILIT_API_KEY", "").strip()
    if not key and not args.dry_run:
        print("ERROR: EMAILIT_API_KEY is not set.", file=sys.stderr)
        return 2

    mf = json.loads(Path(args.manifest).read_text())
    sender = os.environ.get("MAIL_FROM", "WP Maintenance <wpmaintenance@fedx.io>")
    recipients = os.environ.get("MAIL_TO", "trevor.lowing@gmail.com")

    html_body = Path(mf["html"]).read_text()
    text_body = Path(mf["md"]).read_text()

    # Prefer the branded PDF; fall back to the Markdown as .txt.
    date_tag = Path(mf["md"]).stem
    if mf.get("pdf") and Path(mf["pdf"]).exists():
        attachment = {"filename": f"{date_tag}.pdf",
                      "content": b64(Path(mf["pdf"])),
                      "content_type": "application/pdf"}
    else:
        attachment = {"filename": f"{date_tag}.txt",
                      "content": base64.b64encode(text_body.encode()).decode(),
                      "content_type": "text/plain"}

    payload = {
        "from": sender,
        "to": recipients,
        "subject": mf["subject"],
        "text": text_body,
        "html": html_body,
        "attachments": [attachment],
    }
    if os.environ.get("MAIL_REPLY_TO"):
        payload["reply_to"] = os.environ["MAIL_REPLY_TO"]

    if args.dry_run:
        print(f"[dry-run] would send '{mf['subject']}' to {recipients} "
              f"with attachment {attachment['filename']} "
              f"({len(attachment['content'])} b64 bytes)")
        return 0

    req = urllib.request.Request(
        API, data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Idempotency-Key": "wp-health-" + uuid.uuid4().hex,
        }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            print("HTTP", r.status)
            print(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print("HTTP", e.code)
        print(e.read().decode("utf-8"))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
