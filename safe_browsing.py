"""
safe_browsing.py
------------------
Optional integration with Google's Safe Browsing API, which checks a
URL against Google's own database of known malicious sites - a
different, complementary signal to the lookalike-domain detection
built elsewhere in this project (that catches NEW scam domains that
look like a brand; this catches sites Google has already confirmed
as malicious).

SECURITY NOTE - read this before deploying:
This requires a free Google Cloud API key. That key is NEVER
hardcoded here, never logged, and never sent anywhere except Google's
own API endpoint over HTTPS. It is read exclusively from the
GOOGLE_SAFE_BROWSING_API_KEY environment variable.

Setup:
1. Get a free API key: https://developers.google.com/safe-browsing/v4/get-started
2. Set it as an environment variable - NEVER put it directly in code
   or commit it to git:
     Local:  export GOOGLE_SAFE_BROWSING_API_KEY="your-key-here"
     Render: Dashboard -> your service -> Environment -> Add variable
3. If this variable is not set, this module cleanly no-ops - the rest
   of the app works fully without it, just without this one extra
   signal.
"""

import os
import requests


SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def is_configured() -> bool:
    return bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"))


def check_url(url: str, timeout: int = 5) -> dict:
    """Returns a dict with keys: checked (bool), is_threat (bool),
    threat_types (list), error (str). Never raises - a failed or
    unconfigured check is itself just a piece of data the caller can
    handle, not a crash."""
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        return {"checked": False, "is_threat": False, "threat_types": [], "error": "not_configured"}

    payload = {
        "client": {"clientId": "scam-shield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        matches = data.get("matches", [])
        threat_types = [m.get("threatType") for m in matches]
        return {"checked": True, "is_threat": bool(matches), "threat_types": threat_types, "error": ""}
    except requests.exceptions.RequestException as e:
        # Never let a failed API call surface the API key even in an
        # error message - str(e) from requests doesn't include the
        # key itself since it's a query param handled internally, but
        # we scrub defensively anyway.
        safe_error = str(e).replace(api_key, "[REDACTED]")
        return {"checked": False, "is_threat": False, "threat_types": [], "error": safe_error}
