"""
link_analysis.py
-----------------
Extracts URLs from an email body and analyzes the domains they point
to - most notably, typosquatting detection: catching lookalike domains
like 'paypa1.com' or 'micros0ft-support.com' that are visually close
to a well-known brand but aren't actually that brand's domain.

This is done with Levenshtein (edit) distance against a curated list
of commonly-impersonated brand domains, rather than just checking
against a keyword blocklist - which means it catches variations that
haven't been seen before, not just known-bad exact matches.
"""

import re
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

# Commonly impersonated brands in phishing campaigns. This list is
# intentionally small and curated rather than exhaustive - the goal is
# catching the highest-value targets, not building a universal
# database (that's what commercial threat-intel feeds are for).
KNOWN_BRAND_DOMAINS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "netflix.com", "bankofamerica.com", "wellsfargo.com", "chase.com",
    "americanexpress.com", "facebook.com", "instagram.com", "linkedin.com",
    "dropbox.com", "docusign.com", "irs.gov", "usps.com", "fedex.com",
    "ups.com", "coinbase.com", "venmo.com", "zelle.com",
]

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


@dataclass
class LinkFinding:
    url: str
    domain: str
    is_typosquat: bool
    typosquat_target: str  # which brand it resembles, if any
    edit_distance: int
    is_combosquat: bool
    combosquat_target: str
    is_ip_address: bool
    uses_url_shortener: bool


URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                   "is.gd", "buff.ly", "rebrand.ly", "shorturl.at"}


def _is_ip_address(domain: str) -> bool:
    """Recognize valid IPv4 and IPv6 literals without treating 999.1.1.1 as one."""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _levenshtein(a: str, b: str) -> int:
    """Standard edit-distance calculation: minimum number of
    single-character insertions, deletions, or substitutions needed
    to turn string a into string b."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def extract_urls(text: str, html: str = "") -> list:
    """Pulls URLs out of both the plain-text and HTML bodies. HTML
    bodies matter because a phishing email's visible link text can say
    'paypal.com' while the actual href underneath points somewhere
    else entirely - so we specifically also look inside href attributes."""
    urls = {url.rstrip(".,;:!?") for url in URL_PATTERN.findall(text or "")}

    if html:
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for href in href_pattern.findall(html):
            if href.startswith("http"):
                urls.add(href)

    return list(urls)


def _is_legitimate_subdomain(domain: str) -> bool:
    """Returns True if domain IS a known brand, or is a legitimate
    subdomain of one (e.g. 'www.paypal.com' or 'mail.google.com').
    This must be checked BEFORE any typosquat/combosquat logic, or
    real brand domains get false-flagged just for having a subdomain
    prefix."""
    domain = domain.lower().strip()
    for brand in KNOWN_BRAND_DOMAINS:
        if domain == brand or domain.endswith("." + brand):
            return True
    return False


def _domain_tokens(domain: str) -> list:
    """Splits a domain's SLD into word-like tokens so we can catch
    brand names/lookalikes embedded alongside other words, e.g.
    'paypa1-security.com' -> ['paypa1', 'security']. Without this, a
    hyphenated domain's overall edit distance to the real brand domain
    is huge (extra words inflate the distance) even though one token
    is clearly a one-character-off lookalike."""
    sld = domain.split(".")[0] if "." in domain else domain
    return [t for t in re.split(r"[-_.]", sld) if t]


def check_typosquat(domain: str, threshold: int = 2) -> tuple:
    """Checks each token of a domain against known brand names using
    edit distance. Catches both 'paypa1.com' (whole SLD is off by one)
    and 'paypa1-security.com' (one token is off by one, plus extra
    words) - character-substitution lookalikes in either form."""
    domain = domain.lower().strip()

    if _is_legitimate_subdomain(domain):
        return False, "", 0

    tokens = _domain_tokens(domain)
    best_match = ""
    best_distance = 999

    for brand in KNOWN_BRAND_DOMAINS:
        brand_name = brand.split(".")[0]
        for token in tokens:
            if abs(len(token) - len(brand_name)) > threshold:
                continue
            distance = _levenshtein(token, brand_name)
            if distance < best_distance:
                best_distance = distance
                best_match = brand

    is_typosquat = 0 < best_distance <= threshold
    return is_typosquat, (best_match if is_typosquat else ""), best_distance


def check_combosquat(domain: str) -> tuple:
    """Catches a different, arguably more common pattern than
    character-substitution typosquats: a brand name embedded as a
    substring inside a longer domain that isn't actually owned by that
    brand - e.g. 'paypal-security-verify.com' or
    'amazon-account-update.net'. Edit distance alone misses these
    because the domains are a very different LENGTH from the real
    brand domain, even though they're clearly designed to look
    trustworthy at a glance."""
    domain = domain.lower().strip()

    if _is_legitimate_subdomain(domain):
        return False, ""

    sld = domain.split(".")[0] if "." in domain else domain

    for brand in KNOWN_BRAND_DOMAINS:
        brand_name = brand.split(".")[0]  # "paypal" from "paypal.com"
        if len(brand_name) < 4:
            continue  # skip very short brand names, too many false positives
        if brand_name in sld:
            return True, brand

    return False, ""


def analyze_links(text_body: str, html_body: str = "") -> list:
    """Main entry point: extracts every URL and runs the full analysis
    pipeline on each one's domain."""
    urls = extract_urls(text_body, html_body)
    findings = []

    for url in urls:
        try:
            parsed = urlparse(url)
            # hostname handles userinfo and ports correctly and avoids treating
            # a trailing root-domain dot as a different domain.
            domain = (parsed.hostname or "").rstrip(".").lower()
        except Exception:
            continue

        if not domain:
            continue

        is_ip = _is_ip_address(domain)
        is_shortener = domain in URL_SHORTENERS

        is_typo, target, distance = (False, "", 0) if is_ip else check_typosquat(domain)
        is_combo, combo_target = (False, "") if is_ip else check_combosquat(domain)

        findings.append(LinkFinding(
            url=url,
            domain=domain,
            is_typosquat=is_typo,
            typosquat_target=target,
            edit_distance=distance,
            is_combosquat=is_combo,
            combosquat_target=combo_target,
            is_ip_address=is_ip,
            uses_url_shortener=is_shortener,
        ))

    return findings
