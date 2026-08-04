from website_analysis import (
    WebsiteReport, score_domain_age, score_ssl, score_redirect_chain,
    score_payment_language, score_domain_lookalike, score_ip_address_url, _is_public_target,
)


def _make_report(**overrides):
    defaults = dict(
        url="http://example.com", domain="example.com", domain_age_days=-1,
        has_valid_ssl=True, ssl_error="", redirect_chain=["http://example.com"],
        final_url="http://example.com", page_text_sample="", fetch_error="",
    )
    defaults.update(overrides)
    return WebsiteReport(**defaults)


def test_very_new_domain_scores_high():
    reasons = score_domain_age(3)
    assert len(reasons) == 1
    assert reasons[0].points == 35


def test_established_domain_scores_nothing():
    reasons = score_domain_age(400)
    assert reasons == []


def test_unknown_domain_age_scores_low_not_zero():
    reasons = score_domain_age(-1)
    assert len(reasons) == 1
    assert reasons[0].points == 10


def test_missing_ssl_flagged():
    report = _make_report(has_valid_ssl=False, fetch_error="")
    reasons = score_ssl(report)
    assert len(reasons) == 1


def test_missing_ssl_not_flagged_if_site_unreachable():
    # A site that's completely unreachable shouldn't ALSO get dinged
    # for "no SSL" - that's a separate, already-covered signal
    report = _make_report(has_valid_ssl=False, fetch_error="Connection refused")
    reasons = score_ssl(report)
    assert reasons == []


def test_long_redirect_chain_flagged():
    report = _make_report(redirect_chain=["http://a.com", "http://b.com", "http://c.com", "http://d.com", "http://e.com"])
    reasons = score_redirect_chain(report)
    assert len(reasons) == 1


def test_short_redirect_chain_not_flagged():
    report = _make_report(redirect_chain=["http://a.com", "http://b.com"])
    reasons = score_redirect_chain(report)
    assert reasons == []


def test_scam_payment_language_detected():
    reasons = score_payment_language("Pay now via gift card or wire transfer only. No refunds.")
    assert len(reasons) == 1
    assert reasons[0].points == 30


def test_normal_payment_language_not_flagged():
    reasons = score_payment_language("We accept Visa, Mastercard, and PayPal.")
    assert reasons == []


def test_empty_page_text_handled():
    reasons = score_payment_language("")
    assert reasons == []


def test_real_brand_domain_not_flagged_as_lookalike():
    reasons = score_domain_lookalike("paypal.com")
    assert reasons == []


def test_typosquat_domain_flagged():
    reasons = score_domain_lookalike("paypa1-rewards.com")
    assert len(reasons) == 1
    assert "paypal.com" in reasons[0].reason


def test_ip_address_domain_flagged():
    reasons = score_ip_address_url("192.168.1.1")
    assert len(reasons) == 1
    assert reasons[0].points == 15


def test_normal_domain_not_flagged_as_ip():
    reasons = score_ip_address_url("example.com")
    assert reasons == []


def test_private_and_loopback_fetch_targets_are_rejected():
    assert _is_public_target("http://127.0.0.1/admin") is False
    assert _is_public_target("http://192.168.1.1/") is False
    assert _is_public_target("http://localhost/") is False


def test_fetch_errors_are_safe_for_user_facing_reports(monkeypatch):
    import requests
    from website_analysis import fetch_website

    monkeypatch.setattr("website_analysis._is_public_target", lambda url: True)
    monkeypatch.setattr("website_analysis.requests.get", lambda *args, **kwargs: (_ for _ in ()).throw(
        requests.exceptions.ConnectionError("internal proxy hostname should not be shown")
    ))
    report = fetch_website("https://example.com")
    assert report.fetch_error == "The site could not be reached or verified"


def test_full_scam_scenario_scores_dangerous():
    """End-to-end style test using a fully mocked report - simulates
    what a real scam site's fetch results would look like, without
    needing to fetch (or worse, actually visit) a real one."""
    from scoring import compute_verdict, score_urgency_language, ScoreReason

    report = _make_report(
        domain="paypa1-rewards-claim.com",
        domain_age_days=3,
        has_valid_ssl=False,
        redirect_chain=["http://bit.ly/x", "http://mid.net", "http://paypa1-rewards-claim.com"],
        page_text_sample="URGENT! Act immediately. Payment must be sent first via gift card only.",
    )

    reasons = []
    reasons.extend(score_domain_lookalike(report.domain))
    reasons.extend(score_domain_age(report.domain_age_days))
    reasons.extend(score_ssl(report))
    reasons.extend(score_redirect_chain(report))
    reasons.extend(score_payment_language(report.page_text_sample))
    points, matches = score_urgency_language(report.page_text_sample)
    if points:
        reasons.append(ScoreReason(points, "urgency"))

    total = min(sum(r.points for r in reasons), 100)
    assert compute_verdict(total) == "DANGEROUS"


def test_full_clean_scenario_scores_safe():
    from scoring import compute_verdict

    report = _make_report(
        domain="example.com",
        domain_age_days=3650,
        has_valid_ssl=True,
        redirect_chain=["http://example.com"],
        page_text_sample="Welcome to our store. We accept all major credit cards.",
    )

    reasons = []
    reasons.extend(score_domain_lookalike(report.domain))
    reasons.extend(score_domain_age(report.domain_age_days))
    reasons.extend(score_ssl(report))
    reasons.extend(score_redirect_chain(report))
    reasons.extend(score_payment_language(report.page_text_sample))

    total = min(sum(r.points for r in reasons), 100)
    assert compute_verdict(total) == "SAFE"
