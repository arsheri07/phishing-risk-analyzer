from email_parser import parse_email, get_sender_domain

LEGIT_EMAIL = """From: GitHub <notifications@github.com>
Reply-To: notifications@github.com
Subject: New comment on your PR
Date: Mon, 20 Jul 2026 14:22:00 +0000
Content-Type: text/plain

View it here: https://github.com/octocat/repo/pull/42
"""

PHISHING_EMAIL = """From: PayPal Security <alerts@paypa1-security.com>
Reply-To: support@totally-different-domain.ru
Subject: Urgent: verify now
Date: Mon, 20 Jul 2026 03:12:00 +0000
Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail
Content-Type: text/plain

Click here: http://paypa1-security.com/verify
"""


def test_parses_from_address_and_display_name():
    parsed = parse_email(PHISHING_EMAIL)
    assert parsed.from_address == "alerts@paypa1-security.com"
    assert parsed.from_display_name == "PayPal Security"


def test_parses_reply_to():
    parsed = parse_email(PHISHING_EMAIL)
    assert parsed.reply_to == "support@totally-different-domain.ru"


def test_parses_subject():
    parsed = parse_email(LEGIT_EMAIL)
    assert parsed.subject == "New comment on your PR"


def test_parses_authentication_results_header():
    parsed = parse_email(PHISHING_EMAIL)
    assert "spf=fail" in parsed.authentication_results


def test_missing_authentication_results_is_empty_not_crash():
    parsed = parse_email(LEGIT_EMAIL)
    assert parsed.authentication_results == ""


def test_get_sender_domain():
    assert get_sender_domain("alerts@paypa1-security.com") == "paypa1-security.com"
    assert get_sender_domain("") == ""
    assert get_sender_domain("not-an-email") == ""


def test_body_text_extracted():
    parsed = parse_email(LEGIT_EMAIL)
    assert "github.com/octocat" in parsed.body_text
