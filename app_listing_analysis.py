"""
app_listing_analysis.py
------------------------
Analyzes an app store listing (paste the app name, developer name,
description, and requested permissions) for fake-app scam indicators.

Note on scope: this checks the LISTING TEXT, not the app's actual
binary/APK. Real APK analysis (checking actual code behavior, not just
the store description) is a much deeper static-analysis project on
its own - this module is intentionally scoped to what's checkable from
public listing text alone, which is often where a fake app's biggest
red flags already show up (mismatched permissions, "guaranteed"
financial claims, generic developer names).
"""

import re
from dataclasses import dataclass

from scoring import ScoreReason, compute_verdict, AnalysisResult


# Financial/investment apps promising guaranteed, risk-free, or
# unrealistic returns are one of the clearest fake-app patterns -
# no legitimate financial product can honestly promise this.
TOO_GOOD_TO_BE_TRUE_PHRASES = [
    "guaranteed profit", "guaranteed returns", "risk-free investment",
    "double your money", "100% guaranteed", "unlimited free",
    "no risk", "guaranteed income", "get rich", "passive income guaranteed",
]

# Rough keyword groups for simple apps, mapped to the permissions
# that type of app can legitimately need. A flashlight app needs
# camera access (to control the flash) - that's normal, not a red
# flag. Contacts/SMS/location for a flashlight app is not normal.
LOW_PERMISSION_APP_PROFILES = {
    "flashlight": {"keywords": ["flashlight", "torch light"], "acceptable": ["camera"]},
    "calculator": {"keywords": ["calculator"], "acceptable": []},
    "qr scanner": {"keywords": ["qr code scanner", "qr scanner", "barcode scanner"], "acceptable": ["camera"]},
    "wallpaper": {"keywords": ["wallpaper app", "wallpapers hd"], "acceptable": ["storage"]},
}

SENSITIVE_PERMISSIONS = [
    "contacts", "sms", "call log", "microphone", "camera", "location",
    "read messages", "device admin", "accessibility service",
]

GENERIC_DEVELOPER_PATTERN = re.compile(
    r"^(app|studio|dev|tech|soft)\s*\d{2,}$|^\w{1,4}\d{3,}$", re.IGNORECASE
)


@dataclass
class AppListingReport:
    app_name: str
    developer_name: str
    description: str
    permissions: list
    matched_ttgt_phrases: list
    permission_mismatch: bool
    generic_developer_name: bool


def score_too_good_to_be_true(description: str) -> list:
    if not description:
        return []
    text_lower = description.lower()
    matched = [p for p in TOO_GOOD_TO_BE_TRUE_PHRASES if p in text_lower]
    if matched:
        return [ScoreReason(35, f"Description makes unrealistic financial claims ({', '.join(matched[:3])}) - a strong indicator of a fake investment/earning app")]
    return []


def score_permission_mismatch(description: str, permissions: list) -> list:
    """Flags a simple-sounding app (per its own description) that
    requests permissions far beyond what that kind of app would ever
    legitimately need - while still allowing the specific permissions
    that ARE normal for that app type (e.g. camera access for a
    flashlight app, which controls the physical flash)."""
    if not description or not permissions:
        return []

    description_lower = description.lower()
    permissions_lower = [p.strip().lower() for p in permissions]

    for app_type, profile in LOW_PERMISSION_APP_PROFILES.items():
        if any(kw in description_lower for kw in profile["keywords"]):
            matched_sensitive = [
                p for p in SENSITIVE_PERMISSIONS
                if any(p in perm for perm in permissions_lower) and p not in profile["acceptable"]
            ]
            if matched_sensitive:
                return [ScoreReason(
                    40,
                    f"App describes itself as a simple {app_type} app but requests sensitive permissions "
                    f"it shouldn't need ({', '.join(matched_sensitive)}) - a common pattern for data-harvesting fake apps"
                )]
    return []


def score_generic_developer_name(developer_name: str) -> list:
    if not developer_name:
        return []
    if GENERIC_DEVELOPER_PATTERN.match(developer_name.strip()):
        return [ScoreReason(15, f"Developer name '{developer_name}' follows a generic auto-generated pattern rather than an identifiable company or individual")]
    return []


def analyze_app_listing(app_name: str, developer_name: str, description: str, permissions_text: str) -> tuple:
    """Main entry point. permissions_text is a comma or newline
    separated list of requested permissions, as typically shown on a
    store listing's 'App permissions' section."""
    permissions = [p.strip() for p in re.split(r"[,\n]", permissions_text or "") if p.strip()]

    reasons = []
    reasons.extend(score_too_good_to_be_true(description))
    reasons.extend(score_permission_mismatch(description, permissions))
    reasons.extend(score_generic_developer_name(developer_name))

    total_score = min(sum(r.points for r in reasons), 100)
    verdict = compute_verdict(total_score)

    text_lower = (description or "").lower()
    report = AppListingReport(
        app_name=app_name, developer_name=developer_name, description=description,
        permissions=permissions,
        matched_ttgt_phrases=[p for p in TOO_GOOD_TO_BE_TRUE_PHRASES if p in text_lower],
        permission_mismatch=bool(score_permission_mismatch(description, permissions)),
        generic_developer_name=bool(GENERIC_DEVELOPER_PATTERN.match((developer_name or "").strip())),
    )

    return report, AnalysisResult(verdict=verdict, score=total_score, reasons=reasons)
