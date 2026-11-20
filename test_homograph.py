"""Tests for IDN homograph detection and deceptive link text.

Each attack test has a matching control: real brand domains, legitimate
non-Latin domains, and links whose text honestly matches their href must
stay quiet.
"""

from link_analysis import (check_homograph, to_unicode, analyze_links,
                           find_deceptive_anchors)
from scoring import score_links
from sms_analysis import analyze_sms
from website_analysis import score_domain_lookalike


# --- homographs -----------------------------------------------------------

def test_single_cyrillic_letter_swap_detected():
    # 'а' below is CYRILLIC SMALL LETTER A (U+0430)
    is_homo, target, uni, mixed = check_homograph("аpple.com")
    assert is_homo and target == "apple.com"
    assert mixed  # Cyrillic а next to Latin pple


def test_all_cyrillic_lookalike_detected():
    """'аррӏе' is five edits from 'apple', so edit distance alone misses it."""
    is_homo, target, _, _ = check_homograph("аррӏе.com")
    assert is_homo and target == "apple.com"


def test_punycode_form_is_decoded_and_detected():
    puny = "рaypal.com".encode("idna").decode()
    assert puny.startswith("xn--")
    is_homo, target, uni, _ = check_homograph(puny)
    assert is_homo and target == "paypal.com"
    assert uni == "рaypal.com"


def test_greek_omicron_detected():
    is_homo, target, _, _ = check_homograph("gοοgle.com")
    assert is_homo and target == "google.com"


def test_homograph_brand_with_extra_words_detected():
    is_homo, target, _, _ = check_homograph("рaypal-login.com")
    assert is_homo and target == "paypal.com"


def test_real_ascii_brand_is_not_a_homograph():
    assert check_homograph("paypal.com")[0] is False
    assert check_homograph("www.apple.com")[0] is False


def test_legitimate_cyrillic_domain_not_flagged_as_brand():
    """A genuine Russian site ('пример.рф' = 'example.rf') is single-script
    and doesn't skeleton to a brand, so it must not be called an attack."""
    is_homo, target, _, mixed = check_homograph("пример.рф")
    assert is_homo is False and mixed is False


def test_malformed_punycode_does_not_crash():
    assert to_unicode("xn--zz!!.com") == "xn--zz!!.com"


# --- deceptive link text --------------------------------------------------

def test_link_text_domain_mismatch_detected():
    html = '<a href="https://secure-login.example.net/x">www.paypal.com</a>'
    assert find_deceptive_anchors(html) == {
        "https://secure-login.example.net/x": "www.paypal.com"}


def test_link_text_matching_href_not_flagged():
    html = '<a href="https://www.paypal.com/signin">paypal.com/signin</a>'
    assert find_deceptive_anchors(html) == {}


def test_subdomain_of_same_site_not_flagged():
    html = '<a href="https://click.mail.chase.com/t/1">www.chase.com</a>'
    assert find_deceptive_anchors(html) == {}


def test_ordinary_link_text_not_flagged():
    html = '<a href="https://anything.example/x">Click here</a>'
    assert find_deceptive_anchors(html) == {}


def test_nested_tags_in_anchor_text_handled():
    html = '<a class="btn" href="https://evil.example/"><b>apple.com</b></a>'
    assert find_deceptive_anchors(html) == {"https://evil.example/": "apple.com"}


# --- end to end through every module ------------------------------------

def test_email_scoring_explains_both_tricks():
    html = '<a href="https://рaypal.com/verify">https://www.paypal.com</a>'
    findings = analyze_links("", html)
    assert len(findings) == 1 and findings[0].is_homograph
    reasons = [r.reason for r in score_links(findings)]
    assert any("homograph" in r for r in reasons)
    assert any("Link text shows" in r for r in reasons)
    # not double-counted as a typosquat of the same swapped letter
    assert not any("edit distance" in r for r in reasons)


def test_sms_flags_homograph_link():
    _, result = analyze_sms("Your parcel is held: https://аmazon.com/track")
    assert any("homograph" in r.reason for r in result.reasons)
    assert result.verdict in ("SUSPICIOUS", "DANGEROUS")


def test_website_flags_homograph_domain():
    reasons = score_domain_lookalike("аpple.com")
    assert len(reasons) == 1 and "homograph" in reasons[0].reason


def test_email_parser_preserves_non_ascii_body():
    """Regression: 8-bit bodies used to come back with '\\u0430' escapes,
    which hid homograph links from detection entirely."""
    from email_parser import parse_email
    raw = ("From: a@b.com\nSubject: x\nContent-Type: text/html\n\n"
           '<a href="https://рaypal.com/x">https://www.paypal.com</a>')
    parsed = parse_email(raw)
    assert "рaypal.com" in parsed.body_html
    assert "\\u" not in parsed.body_html
