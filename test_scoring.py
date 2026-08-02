from scoring import (
    score_urgency_language, compute_verdict, score_auth_results,
    analyze_email,
)
from auth_checks import AuthResult
from email_parser import parse_email


def test_urgency_language_detected():
    text = "Your account will be suspended within 24 hours. Act now to avoid suspension."
    points, matched = score_urgency_language(text)
    assert points > 0
    assert len(matched) >= 2


def test_no_urgency_language_scores_zero():
    text = "Hi, just checking in about our meeting tomorrow."
    points, matched = score_urgency_language(text)
    assert points == 0
    assert matched == []


def test_urgency_score_has_diminishing_returns_cap():
    # Even with many matches, the score should be capped, not unbounded
    text = " ".join([
        "act now", "act immediately", "urgent action required", "verify immediately",
        "unusual activity", "final notice", "immediate attention required",
    ])
    points, matched = score_urgency_language(text)
    assert points <= 30


def test_verdict_thresholds():
    assert compute_verdict(0) == "SAFE"
    assert compute_verdict(19) == "SAFE"
    assert compute_verdict(20) == "SUSPICIOUS"
    assert compute_verdict(49) == "SUSPICIOUS"
    assert compute_verdict(50) == "DANGEROUS"
    assert compute_verdict(100) == "DANGEROUS"


def test_spf_fail_scores_high():
    auth = AuthResult(spf="fail", dkim="pass", dmarc="pass", source="header", details=[])
    reasons = score_auth_results(auth)
    assert any(r.points == 25 for r in reasons)


def test_all_auth_pass_produces_no_reasons():
    auth = AuthResult(spf="pass", dkim="pass", dmarc="pass", source="header", details=[])
    reasons = score_auth_results(auth)
    assert reasons == []


def test_full_pipeline_flags_phishing_email_as_dangerous():
    phishing_email = """From: PayPal Security <alerts@paypa1-security.com>
Reply-To: support@totally-different.ru
Subject: Urgent: verify immediately
Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail
Content-Type: text/plain

Your account will be suspended within 24 hours. Verify immediately: http://paypa1-security.com/verify
"""
    from link_analysis import analyze_links
    parsed = parse_email(phishing_email)
    auth = AuthResult(spf="fail", dkim="none", dmarc="fail", source="header", details=[])
    links = analyze_links(parsed.body_text, parsed.body_html)

    result = analyze_email(parsed, auth, links)
    assert result.verdict == "DANGEROUS"
    assert result.score >= 50


def test_full_pipeline_flags_clean_email_as_safe():
    legit_email = """From: GitHub <notifications@github.com>
Reply-To: notifications@github.com
Subject: New comment on your PR
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

View it here: https://github.com/octocat/repo/pull/42
"""
    from link_analysis import analyze_links
    parsed = parse_email(legit_email)
    auth = AuthResult(spf="pass", dkim="pass", dmarc="pass", source="header", details=[])
    links = analyze_links(parsed.body_text, parsed.body_html)

    result = analyze_email(parsed, auth, links)
    assert result.verdict == "SAFE"
    assert result.score == 0
