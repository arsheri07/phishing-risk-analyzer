"""
scoring.py
----------
Combines authentication results, link analysis findings, and
urgency/pressure language into a single explainable verdict.

Design principle carried over from the network log analyzer project:
every point added to the score comes with a human-readable reason.
Nothing is a black-box number - if a report is flagged HIGH risk, the
person using it should be able to see exactly why.
"""

import re
from dataclasses import dataclass, field


@dataclass
class ScoreReason:
    points: int
    reason: str


@dataclass
class AnalysisResult:
    verdict: str          # "SAFE" | "SUSPICIOUS" | "DANGEROUS"
    score: int             # 0-100
    reasons: list           # list of ScoreReason


# Phrases commonly used to create false urgency and pressure quick,
# unthinking action - the psychological core of most phishing attacks.
URGENCY_PHRASES = [
    "act now", "act immediately", "urgent action required", "verify immediately",
    "account will be suspended", "account has been limited", "confirm your identity",
    "unusual activity", "click here immediately", "within 24 hours", "within 48 hours",
    "your account will be closed", "final notice", "immediate attention required",
    "failure to respond", "avoid suspension", "restricted access", "unauthorized access detected",
]


def find_phrases(text: str, phrases: list[str]) -> list[str]:
    """Return complete phrase matches, avoiding substring false positives.

    Security terms are often short (for example, ``irs``). A raw
    ``phrase in text`` check would flag harmless words such as ``first``.
    Boundaries also keep ``contact now`` from matching the separate phrase
    ``act now``.
    """
    if not text:
        return []
    return [
        phrase for phrase in phrases
        if re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text, re.IGNORECASE)
    ]


def score_urgency_language(text: str) -> tuple:
    """Scans body text for pressure/urgency phrases. Returns (score
    contribution, list of matched phrases). Case-insensitive since
    phishing emails vary capitalization to dodge simple filters."""
    if not text:
        return 0, []

    matched = find_phrases(text, URGENCY_PHRASES)

    # Diminishing returns per additional phrase - 3 urgency phrases
    # isn't 3x as suspicious as 1, but it's still worse than 1
    points = min(len(matched) * 8, 30)
    return points, matched


def score_auth_results(auth_result) -> list:
    """Turns SPF/DKIM/DMARC verdicts into scored, explained reasons."""
    reasons = []

    if auth_result.spf == "fail":
        reasons.append(ScoreReason(25, "SPF check FAILED - sending server is not authorized to send mail for this domain"))
    elif auth_result.spf in ("no_record", "none"):
        reasons.append(ScoreReason(10, "Sender domain has no SPF record - legitimate organizations almost always publish one"))
    elif auth_result.spf == "softfail":
        reasons.append(ScoreReason(15, "SPF check soft-failed - sender is suspicious but not explicitly rejected"))

    if auth_result.dkim == "fail":
        reasons.append(ScoreReason(25, "DKIM signature is invalid - message may have been altered in transit or is forged"))
    elif auth_result.dkim == "none":
        reasons.append(ScoreReason(10, "No DKIM signature present - message authenticity cannot be verified"))

    if auth_result.dmarc in ("fail", "reject"):
        reasons.append(ScoreReason(20, "DMARC check failed or policy indicates this message should be rejected"))
    elif auth_result.dmarc == "none" or auth_result.dmarc == "no_record":
        reasons.append(ScoreReason(5, "Sender domain has no DMARC policy - offers no protection against spoofing"))

    return reasons


def score_links(link_findings: list) -> list:
    """Turns link analysis findings into scored, explained reasons."""
    reasons = []

    for finding in link_findings:
        if finding.is_typosquat:
            reasons.append(ScoreReason(
                30,
                f"Link domain '{finding.domain}' closely resembles '{finding.typosquat_target}' "
                f"(edit distance {finding.edit_distance}) - likely impersonation"
            ))
        if finding.is_combosquat:
            reasons.append(ScoreReason(
                25,
                f"Link domain '{finding.domain}' contains the brand name from "
                f"'{finding.combosquat_target}' but is not that domain - likely impersonation"
            ))
        if finding.is_ip_address:
            reasons.append(ScoreReason(
                20,
                f"Link points directly to an IP address ({finding.domain}) rather than a "
                f"domain name - unusual for legitimate business communication"
            ))
        if finding.uses_url_shortener:
            reasons.append(ScoreReason(
                10,
                f"Link uses a URL shortener ({finding.domain}), which hides the real "
                f"destination until clicked"
            ))

    return reasons


def score_sender_mismatch(parsed_email) -> list:
    """Checks for a classic phishing tell: the Reply-To address
    doesn't match the From address. Legitimate organizations sometimes
    do this intentionally, but combined with other signals it's
    meaningful - an attacker spoofs a trusted From address but needs
    replies routed to an address they actually control."""
    reasons = []

    if parsed_email.reply_to and parsed_email.reply_to != parsed_email.from_address:
        from_domain = parsed_email.from_address.split("@")[-1] if "@" in parsed_email.from_address else ""
        reply_domain = parsed_email.reply_to.split("@")[-1] if "@" in parsed_email.reply_to else ""
        if from_domain != reply_domain:
            reasons.append(ScoreReason(
                15,
                f"Reply-To address ({parsed_email.reply_to}) uses a different domain than "
                f"the From address ({parsed_email.from_address}) - replies would go somewhere unexpected"
            ))

    return reasons


def compute_verdict(score: int) -> str:
    """Maps a numeric score to a human verdict. Thresholds are
    intentionally conservative on the SAFE side - a false 'SAFE' on an
    actual phishing email is a much worse outcome than a false alarm
    on a legitimate one, so the bar to reach SAFE is meant to require
    genuinely clean signals across the board."""
    if score >= 50:
        return "DANGEROUS"
    elif score >= 20:
        return "SUSPICIOUS"
    else:
        return "SAFE"


def analyze_email(parsed_email, auth_result, link_findings) -> AnalysisResult:
    """Main entry point for email analysis: runs every scoring function
    and combines the results into one final, fully-explained verdict."""
    reasons = []
    reasons.extend(score_auth_results(auth_result))
    reasons.extend(score_links(link_findings))
    reasons.extend(score_sender_mismatch(parsed_email))

    urgency_points, urgency_matches = score_urgency_language(
        parsed_email.body_text + " " + parsed_email.body_html
    )
    if urgency_points > 0:
        phrase_list = ", ".join(f'"{p}"' for p in urgency_matches[:3])
        reasons.append(ScoreReason(
            urgency_points,
            f"Body contains urgency/pressure language ({phrase_list}"
            f"{', and more' if len(urgency_matches) > 3 else ''})"
        ))

    total_score = min(sum(r.points for r in reasons), 100)
    verdict = compute_verdict(total_score)

    return AnalysisResult(verdict=verdict, score=total_score, reasons=reasons)
