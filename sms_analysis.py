"""
sms_analysis.py
----------------
Analyzes a raw SMS/text message for scam indicators. Shares the link
analysis and urgency-language scoring built for email and websites,
and adds patterns specific to SMS scams ("smishing") - fake package
delivery links, fake prize/lottery notifications, and one-time-code
phishing (tricking someone into forwarding a real login code).
"""

import re
from dataclasses import dataclass

from link_analysis import analyze_links
from scoring import ScoreReason, score_urgency_language, compute_verdict, AnalysisResult


# Patterns specific to SMS scams that don't overlap much with email
# urgency language - these are short-form, mobile-specific hooks.
SMISHING_PHRASES = [
    "your package is on hold", "delivery failed", "redeliver your package",
    "you've won", "you have won", "claim your prize", "claim your reward",
    "verification code", "do not share this code", "forward this code",
    "your account has been flagged", "unusual sign-in activity",
    "confirm your identity to unlock", "reply stop to unsubscribe",
]

# A real one-time-passcode message asking you to type/enter a code is
# normal. A message asking you to *send/forward/reply with* a code is
# the classic OTP-interception scam pattern - the wording difference
# matters a lot here.
OTP_FORWARDING_PATTERN = re.compile(
    r"(forward|reply with|send us|share)\s+(this|the|your)?\s*code", re.IGNORECASE
)


@dataclass
class SmsReport:
    message: str
    links: list
    matched_phrases: list
    requests_otp_forwarding: bool


def score_smishing_phrases(text: str) -> tuple:
    if not text:
        return 0, []
    text_lower = text.lower()
    matched = [p for p in SMISHING_PHRASES if p in text_lower]
    points = min(len(matched) * 10, 30)
    return points, matched


def score_otp_forwarding(text: str) -> list:
    """This one pattern alone is worth flagging heavily on its own -
    legitimate companies never ask you to forward or read back a code
    you received; that's specifically how OTP-interception scams work."""
    if OTP_FORWARDING_PATTERN.search(text or ""):
        return [ScoreReason(40, "Message asks you to forward, reply with, or share a verification code - legitimate services never ask for this; this is a strong sign of an OTP-interception scam")]
    return []


def analyze_sms(message: str) -> tuple:
    """Main entry point. Returns (SmsReport, AnalysisResult)."""
    links = analyze_links(message, "")

    reasons = []

    smishing_points, matched_phrases = score_smishing_phrases(message)
    if smishing_points:
        phrase_list = ", ".join(f'"{p}"' for p in matched_phrases[:3])
        reasons.append(ScoreReason(smishing_points, f"Contains common smishing phrases ({phrase_list})"))

    reasons.extend(score_otp_forwarding(message))

    urgency_points, urgency_matches = score_urgency_language(message)
    if urgency_points:
        phrase_list = ", ".join(f'"{p}"' for p in urgency_matches[:3])
        reasons.append(ScoreReason(urgency_points, f"Contains urgency/pressure language ({phrase_list})"))

    for link in links:
        if link.is_typosquat:
            reasons.append(ScoreReason(30, f"Link domain '{link.domain}' closely resembles '{link.typosquat_target}' - likely impersonation"))
        if link.is_combosquat:
            reasons.append(ScoreReason(25, f"Link domain '{link.domain}' contains the brand name from '{link.combosquat_target}' but is not that domain"))
        if link.is_ip_address:
            reasons.append(ScoreReason(20, f"Link points directly to a raw IP address ({link.domain})"))
        if link.uses_url_shortener:
            reasons.append(ScoreReason(10, f"Link uses a URL shortener ({link.domain}), hiding the real destination"))

    total_score = min(sum(r.points for r in reasons), 100)
    verdict = compute_verdict(total_score)

    report = SmsReport(
        message=message, links=links, matched_phrases=matched_phrases,
        requests_otp_forwarding=bool(OTP_FORWARDING_PATTERN.search(message or "")),
    )

    return report, AnalysisResult(verdict=verdict, score=total_score, reasons=reasons)
