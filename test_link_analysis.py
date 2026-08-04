from link_analysis import check_typosquat, check_combosquat, analyze_links, extract_urls


def test_real_brand_domain_not_flagged():
    is_typo, target, dist = check_typosquat("paypal.com")
    assert is_typo is False


def test_real_brand_subdomain_not_flagged():
    """A subdomain of a real brand (www.paypal.com) must NOT be
    flagged - this was a real bug caught during development."""
    is_typo, target, dist = check_typosquat("www.paypal.com")
    assert is_typo is False
    is_combo, combo_target = check_combosquat("www.paypal.com")
    assert is_combo is False


def test_character_substitution_typosquat_detected():
    is_typo, target, dist = check_typosquat("paypa1.com")
    assert is_typo is True
    assert target == "paypal.com"
    assert dist == 1


def test_character_substitution_with_extra_words_still_detected():
    """The harder case: 'paypa1-security.com' - the lookalike character
    is buried alongside an extra word, so naive full-string edit
    distance misses it. Tokenizing the domain catches it."""
    is_typo, target, dist = check_typosquat("paypa1-security.com")
    assert is_typo is True
    assert target == "paypal.com"


def test_combosquat_detects_brand_name_embedded_in_domain():
    is_combo, target = check_combosquat("amazon-account-update.net")
    assert is_combo is True
    assert target == "amazon.com"


def test_unrelated_domain_not_flagged():
    is_typo, _, _ = check_typosquat("myfavoriteblog.com")
    is_combo, _ = check_combosquat("myfavoriteblog.com")
    assert is_typo is False
    assert is_combo is False


def test_extract_urls_from_plain_text():
    text = "Click here: http://example.com/verify and also https://second.com"
    urls = extract_urls(text)
    assert "http://example.com/verify" in urls
    assert "https://second.com" in urls


def test_extract_urls_from_html_href():
    html = '<a href="http://phishing-site.com/login">Click here</a>'
    urls = extract_urls("", html)
    assert "http://phishing-site.com/login" in urls


def test_ip_address_link_flagged():
    findings = analyze_links("Visit http://192.168.1.1/admin now")
    assert len(findings) == 1
    assert findings[0].is_ip_address is True


def test_ipv6_link_and_trailing_punctuation_are_handled_correctly():
    findings = analyze_links("Safe: https://paypal.com. Risky: http://[2001:db8::1]/login.")
    by_domain = {finding.domain: finding for finding in findings}
    assert by_domain["paypal.com"].is_combosquat is False
    assert by_domain["2001:db8::1"].is_ip_address is True


def test_url_shortener_flagged():
    findings = analyze_links("Click http://bit.ly/abc123")
    assert len(findings) == 1
    assert findings[0].uses_url_shortener is True


def test_no_links_returns_empty_list():
    findings = analyze_links("This email has no links at all.")
    assert findings == []
