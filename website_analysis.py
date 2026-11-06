"""
website_analysis.py
--------------------
Analyzes a URL for scam website indicators. Reuses the same
lookalike-domain detection and urgency-language scoring built for
Email Forensics, and adds checks specific to live websites:

- Domain age (via WHOIS) - scam sites are almost always registered
  very recently, since they get taken down and replaced constantly
- SSL certificate presence and age - legitimate sites almost always
  have a properly issued certificate; missing or very fresh certs on
  an otherwise "established-looking" site are a signal
- Redirect chains - scam links often bounce through several domains
  before landing on the real payload, to dodge simple blocklists
- Scam-specific payment language - requests for gift cards, wire
  transfers, or crypto-only payment are a much stronger scam signal
  than they'd be for phishing email urgency language alone
"""

import ssl
import socket
import re
import ipaddress
from datetime import datetime, timezone
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests
import whois as whois_lib

from link_analysis import check_typosquat, check_combosquat
from scoring import ScoreReason, score_urgency_language


@dataclass
class WebsiteReport:
    url: str
    domain: str
    domain_age_days: int          # -1 if unknown
    has_valid_ssl: bool
    ssl_error: str
    redirect_chain: list           # list of URLs, in order
    final_url: str
    page_text_sample: str
    fetch_error: str


# Scam listings and romance/advance-fee scams disproportionately push
# payment methods that are hard to trace and impossible to reverse -
# a request for these specific methods is a much stronger signal than
# generic urgency language.
SCAM_PAYMENT_PHRASES = [
    "gift card", "itunes card", "google play card", "steam card",
    "wire transfer only", "western union", "moneygram",
    "bitcoin only", "crypto only", "cryptocurrency only",
    "cash app only", "zelle only", "venmo only",
    "no refunds", "payment must be sent first",
]

MAX_REDIRECTS = 5


def _is_public_target(url: str) -> bool:
    """Reject loopback, private, and otherwise non-public fetch targets.

    Website analysis is performed server-side, so accepting internal addresses
    would turn this feature into an SSRF primitive. Resolve hostnames before
    every request (including redirects) rather than trusting only the first
    URL the user submitted.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost":
        return False
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        # Let the normal fetch path report an unavailable public hostname.
        return True
    try:
        return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)
    except ValueError:
        return False


def fetch_website(url: str, timeout: int = 8) -> WebsiteReport:
    """Fetches a URL, following redirects, and captures what we need
    for analysis. Network failures are captured as data (fetch_error)
    rather than raised, so a dead/unreachable site is itself a
    reportable finding, not a crash."""
    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()
    if not _is_public_target(url):
        raise ValueError("Website analysis only supports publicly reachable HTTP(S) URLs")

    redirect_chain = []
    final_url = url
    page_text = ""
    fetch_error = ""

    try:
        current_url = url
        for _ in range(MAX_REDIRECTS + 1):
            if not _is_public_target(current_url):
                raise ValueError("Redirect target is not publicly reachable")
            response = requests.get(
                current_url, timeout=timeout, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; PhishingRiskAnalyzer/1.0)"}
            )
            redirect_chain.append(response.url)
            if not response.is_redirect:
                final_url = response.url
                page_text = response.text[:5000]
                break
            location = response.headers.get("Location")
            if not location:
                final_url = response.url
                break
            current_url = urljoin(response.url, location)
        else:
            fetch_error = f"Redirect limit of {MAX_REDIRECTS} exceeded"
    except requests.exceptions.RequestException:
        # Network and proxy exception strings can expose server-specific
        # internals. The report only needs to communicate that this signal
        # could not be verified.
        fetch_error = "The site could not be reached or verified"

    domain_age_days = -1
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            domain_age_days = (datetime.now(timezone.utc) - creation).days
    except Exception:
        pass  # domain_age_days stays -1 (unknown) - handled as its own signal

    has_valid_ssl = False
    ssl_error = ""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                has_valid_ssl = True
    except Exception as e:
        ssl_error = str(e)

    return WebsiteReport(
        url=url, domain=domain, domain_age_days=domain_age_days,
        has_valid_ssl=has_valid_ssl, ssl_error=ssl_error,
        redirect_chain=redirect_chain, final_url=final_url,
        page_text_sample=page_text, fetch_error=fetch_error,
    )


def score_domain_age(age_days: int) -> list:
    """Very young domains are one of the single strongest scam-site
    signals - registering a new domain costs a few dollars, so scam
    operations churn through them constantly rather than risk a
    long-lived domain building up a block-list reputation."""
    reasons = []
    if age_days == -1:
        reasons.append(ScoreReason(10, "Domain registration date could not be determined"))
    elif age_days < 30:
        reasons.append(ScoreReason(35, f"Domain was registered only {age_days} day(s) ago - extremely new domains are heavily associated with scam sites"))
    elif age_days < 180:
        reasons.append(ScoreReason(15, f"Domain is only {age_days} days old - worth extra caution on a site asking for payment or personal information"))
    return reasons


def score_ssl(report: WebsiteReport) -> list:
    reasons = []
    if not report.has_valid_ssl and not report.fetch_error:
        reasons.append(ScoreReason(20, "Site does not present a valid SSL certificate - legitimate sites handling any personal or payment info almost always do"))
    return reasons


_IP_DOMAIN_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def score_ip_address_url(domain: str) -> list:
    """A site reachable directly by IP address, with no domain name at
    all, is unusual for any legitimate business - real companies use
    a named domain precisely so customers can recognize and trust it."""
    if _IP_DOMAIN_PATTERN.match(domain):
        return [ScoreReason(15, f"Site is reached directly by IP address ({domain}) rather than a domain name - unusual for legitimate business sites")]
    return []


def score_redirect_chain(report: WebsiteReport) -> list:
    reasons = []
    if len(report.redirect_chain) > 3:
        chain_domains = [urlparse(u).netloc for u in report.redirect_chain]
        reasons.append(ScoreReason(
            15,
            f"Link redirects through {len(report.redirect_chain)} different pages before landing "
            f"({' → '.join(chain_domains[:4])}{'...' if len(chain_domains) > 4 else ''}) - "
            f"long redirect chains are often used to dodge link blocklists"
        ))
    return reasons


def score_payment_language(page_text: str) -> list:
    reasons = []
    if not page_text:
        return reasons
    text_lower = page_text.lower()
    matched = [p for p in SCAM_PAYMENT_PHRASES if p in text_lower]
    if matched:
        reasons.append(ScoreReason(
            30,
            f"Page requests payment via method(s) commonly used in scams: {', '.join(matched[:3])}"
        ))
    return reasons


def score_domain_lookalike(domain: str) -> list:
    """Reuses the exact typosquat/combosquat detectors built for
    Email Forensics - a lookalike domain is just as strong a signal on
    a website as it is in an email link."""
    reasons = []
    is_typo, target, distance = check_typosquat(domain)
    if is_typo:
        reasons.append(ScoreReason(
            30,
            f"Domain '{domain}' closely resembles '{target}' (edit distance {distance}) - likely impersonation"
        ))
    is_combo, combo_target = check_combosquat(domain)
    if is_combo:
        reasons.append(ScoreReason(
            25,
            f"Domain '{domain}' contains the brand name from '{combo_target}' but is not that domain - likely impersonation"
        ))
    return reasons


def analyze_website(url: str) -> tuple:
    """Main entry point. Returns (WebsiteReport, AnalysisResult) so
    the caller has both the raw findings and the scored verdict."""
    from scoring import AnalysisResult, compute_verdict
    from safe_browsing import is_configured, check_url

    report = fetch_website(url)
    reasons = []

    reasons.extend(score_domain_lookalike(report.domain))
    reasons.extend(score_ip_address_url(report.domain))
    if not _IP_DOMAIN_PATTERN.match(report.domain):
        reasons.extend(score_domain_age(report.domain_age_days))
    reasons.extend(score_ssl(report))
    reasons.extend(score_redirect_chain(report))
    reasons.extend(score_payment_language(report.page_text_sample))

    if is_configured():
        sb_result = check_url(url)
        if sb_result["checked"] and sb_result["is_threat"]:
            reasons.append(ScoreReason(
                50,
                f"Google Safe Browsing has flagged this URL as a known threat ({', '.join(sb_result['threat_types'])})"
            ))

    if report.fetch_error:
        reasons.append(ScoreReason(15, f"Site could not be reached ({report.fetch_error[:100]}) - unreachable sites can't be fully verified"))

    urgency_points, urgency_matches = score_urgency_language(report.page_text_sample)
    if urgency_points > 0:
        phrase_list = ", ".join(f'"{p}"' for p in urgency_matches[:3])
        reasons.append(ScoreReason(urgency_points, f"Page contains urgency/pressure language ({phrase_list})"))

    total_score = min(sum(r.points for r in reasons), 100)
    verdict = compute_verdict(total_score)

    return report, AnalysisResult(verdict=verdict, score=total_score, reasons=reasons)
