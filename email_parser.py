"""
parser.py
---------
Parses raw email source (.eml content or pasted raw headers+body) into
a structured object the rest of the analyzer can work with.

Uses Python's built-in `email` package - no external dependency needed
for this part, which keeps parsing reliable and fast.
"""

from dataclasses import dataclass, field
from email import message_from_string
from email.message import Message
from email.utils import parseaddr, getaddresses


@dataclass
class ParsedEmail:
    raw_source: str
    from_address: str
    from_display_name: str
    reply_to: str
    subject: str
    date: str
    received_headers: list
    authentication_results: str
    dkim_signature_present: bool
    body_text: str
    body_html: str
    all_headers: dict


def _get_body(msg: Message) -> tuple[str, str]:
    """Walk a (possibly multipart) email and extract plain text and
    HTML bodies separately, since phishing emails often hide their
    real payload in the HTML part while the plain-text part looks
    innocuous."""
    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue  # skip attachments for now, not analyzing files

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                continue

            if content_type == "text/plain" and not text_body:
                text_body = decoded
            elif content_type == "text/html" and not html_body:
                html_body = decoded
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            decoded = str(msg.get_payload())

        if content_type == "text/html":
            html_body = decoded
        else:
            text_body = decoded

    return text_body, html_body


def parse_email(raw_source: str) -> ParsedEmail:
    """Takes raw email source (the full text you'd get from 'View
    Original' / 'Show Source' in Gmail or Outlook) and returns a
    structured ParsedEmail."""

    msg = message_from_string(raw_source)

    from_header = msg.get("From", "")
    display_name, from_address = parseaddr(from_header)

    reply_to_header = msg.get("Reply-To", "")
    _, reply_to_address = parseaddr(reply_to_header)

    received_headers = msg.get_all("Received", []) or []

    auth_results = msg.get("Authentication-Results", "") or ""

    dkim_present = msg.get("DKIM-Signature") is not None

    text_body, html_body = _get_body(msg)

    all_headers = {k: v for k, v in msg.items()}

    return ParsedEmail(
        raw_source=raw_source,
        from_address=from_address,
        from_display_name=display_name,
        reply_to=reply_to_address,
        subject=msg.get("Subject", "(no subject)"),
        date=msg.get("Date", ""),
        received_headers=received_headers,
        authentication_results=auth_results,
        dkim_signature_present=dkim_present,
        body_text=text_body,
        body_html=html_body,
        all_headers=all_headers,
    )


def get_sender_domain(email_address: str) -> str:
    """Extracts the domain from an email address, e.g.
    'alerts@paypa1-security.com' -> 'paypa1-security.com'"""
    if "@" not in email_address:
        return ""
    return email_address.split("@")[-1].strip().lower()
