"""
phone_analysis.py
------------------
Analyzes a phone call transcript (you type or paste what was said)
for scam-call indicators.

Note on scope: real-time audio transcription would require a paid
speech-to-text API (there's no free, no-API-key way to do this
reliably) - rather than silently depend on a service you'd have to
sign up and pay for, this works on a transcript you provide, which
covers the same detection logic without that dependency. If you later
add an API key for a speech-to-text service, this module's scoring
functions can be reused as-is on the resulting transcript text.
"""

import re
from dataclasses import dataclass

from scoring import ScoreReason, find_phrases, score_urgency_language, compute_verdict, AnalysisResult


# Impersonation of government agencies is one of the single most
# common phone scam patterns - the IRS, Social Security Administration,
# and similar agencies do not call demanding immediate payment or
# threatening arrest.
AGENCY_IMPERSONATION_PHRASES = [
    "irs", "social security administration", "social security number has been suspended",
    "arrest warrant", "you will be arrested", "law enforcement will be dispatched",
    "your social security number is suspended", "medicare", "amazon security team",
    "microsoft support", "windows technical support", "apple support",
]

# Remote-access software is legitimate on its own, but unsolicited
# requests to install it during a cold call are a defining feature of
# tech-support scams specifically.
REMOTE_ACCESS_SOFTWARE = [
    "anydesk", "teamviewer", "ultraviewer", "remote desktop", "screen sharing",
    "logmein", "supremo",
]

PAYMENT_DEMAND_PHRASES = [
    "gift card", "itunes card", "google play card", "wire transfer",
    "western union", "moneygram", "bitcoin", "cryptocurrency", "cash app",
]


@dataclass
class PhoneReport:
    transcript: str
    phone_number: str
    matched_agency_phrases: list
    matched_remote_access: list
    matched_payment_phrases: list


def score_agency_impersonation(text: str) -> list:
    if not text:
        return []
    matched = find_phrases(text, AGENCY_IMPERSONATION_PHRASES)
    if matched:
        return [ScoreReason(35, f"Mentions government/company impersonation patterns commonly used in scam calls ({', '.join(matched[:3])})")]
    return []


def score_remote_access_request(text: str) -> list:
    if not text:
        return []
    matched = find_phrases(text, REMOTE_ACCESS_SOFTWARE)
    if matched:
        return [ScoreReason(35, f"Requests installing remote-access software ({', '.join(matched)}) - a hallmark of tech-support scams; legitimate support rarely cold-calls asking for this")]
    return []


def score_payment_demand(text: str) -> list:
    if not text:
        return []
    matched = find_phrases(text, PAYMENT_DEMAND_PHRASES)
    if matched:
        return [ScoreReason(30, f"Demands payment via method(s) commonly used in scams ({', '.join(matched[:3])}) - untraceable and irreversible")]
    return []


def analyze_phone_call(transcript: str, phone_number: str = "") -> tuple:
    """Main entry point. Returns (PhoneReport, AnalysisResult)."""
    reasons = []

    reasons.extend(score_agency_impersonation(transcript))
    reasons.extend(score_remote_access_request(transcript))
    reasons.extend(score_payment_demand(transcript))

    urgency_points, urgency_matches = score_urgency_language(transcript)
    if urgency_points:
        phrase_list = ", ".join(f'"{p}"' for p in urgency_matches[:3])
        reasons.append(ScoreReason(urgency_points, f"Contains urgency/pressure language ({phrase_list})"))

    total_score = min(sum(r.points for r in reasons), 100)
    verdict = compute_verdict(total_score)

    text_lower = transcript or ""
    report = PhoneReport(
        transcript=transcript,
        phone_number=phone_number,
        matched_agency_phrases=find_phrases(text_lower, AGENCY_IMPERSONATION_PHRASES),
        matched_remote_access=find_phrases(text_lower, REMOTE_ACCESS_SOFTWARE),
        matched_payment_phrases=find_phrases(text_lower, PAYMENT_DEMAND_PHRASES),
    )

    return report, AnalysisResult(verdict=verdict, score=total_score, reasons=reasons)
