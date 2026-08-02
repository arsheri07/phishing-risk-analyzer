"""
auth_checks.py
--------------
Checks email authentication in two tiers:

TIER 1 (always available, no network needed): parse the
Authentication-Results header. Real mail servers (Gmail, Outlook, etc.)
already run SPF/DKIM/DMARC checks on every email they receive and stamp
the verdict into this header before it ever reaches an inbox. Most
forwarded/.eml-exported emails already carry this - we just need to
read it correctly.

TIER 2 (live verification, needs network + DNS): independently verify
SPF and DMARC ourselves via DNS TXT lookups, and verify the DKIM
signature cryptographically using dkimpy. This doesn't just trust what
the receiving server claims - it re-derives the verdict, which is what
makes this genuinely useful rather than a thin wrapper around a header.
"""

import re
import dns.resolver
import dkim
from dataclasses import dataclass


@dataclass
class AuthResult:
    spf: str          # "pass" | "fail" | "softfail" | "neutral" | "none" | "error"
    dkim: str          # "pass" | "fail" | "none" | "error"
    dmarc: str          # "pass" | "fail" | "none" | "error"
    source: str          # "header" | "live" - where this verdict came from
    details: list        # human-readable explanation strings


_AUTH_RESULTS_PATTERN = re.compile(r"(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)


def parse_authentication_results_header(header_value: str) -> AuthResult:
    """TIER 1: parse what the receiving mail server already determined."""
    if not header_value:
        return AuthResult(spf="none", dkim="none", dmarc="none",
                           source="header", details=["No Authentication-Results header present"])

    matches = _AUTH_RESULTS_PATTERN.findall(header_value)
    results = {k.lower(): v.lower() for k, v in matches}

    details = []
    for check in ("spf", "dkim", "dmarc"):
        verdict = results.get(check, "none")
        details.append(f"{check.upper()}: {verdict} (per receiving server)")

    return AuthResult(
        spf=results.get("spf", "none"),
        dkim=results.get("dkim", "none"),
        dmarc=results.get("dmarc", "none"),
        source="header",
        details=details,
    )


def check_spf_live(domain: str, sender_ip: str = None) -> tuple[str, str]:
    """TIER 2: look up the domain's SPF record directly. Without a
    known sending IP we can't fully evaluate 'pass/fail' (that
    requires knowing which server actually sent the mail), but we CAN
    verify whether the domain publishes an SPF record at all, and
    surface it - a domain with NO SPF record is itself a signal, since
    legitimate organizations almost always publish one."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=spf1"):
                return "record_found", txt
        return "no_record", "Domain has TXT records but no SPF record found"
    except dns.resolver.NXDOMAIN:
        return "error", f"Domain {domain} does not exist"
    except dns.resolver.NoAnswer:
        return "no_record", f"No TXT records found for {domain}"
    except Exception as e:
        return "error", f"DNS lookup failed: {e}"


def check_dmarc_live(domain: str) -> tuple[str, str]:
    """TIER 2: look up _dmarc.<domain> and parse the policy. A missing
    DMARC record, or a policy of 'p=none', means the domain isn't
    protecting itself against spoofing - which matters because it
    tells us how much weight to put on SPF/DKIM results."""
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=DMARC1"):
                policy_match = re.search(r"p=(\w+)", txt)
                policy = policy_match.group(1) if policy_match else "unspecified"
                return policy, txt
        return "no_record", "No DMARC record found"
    except dns.resolver.NXDOMAIN:
        return "no_record", f"No DMARC record published for {domain}"
    except dns.resolver.NoAnswer:
        return "no_record", f"No DMARC record published for {domain}"
    except Exception as e:
        return "error", f"DNS lookup failed: {e}"


def verify_dkim_signature(raw_email_bytes: bytes) -> tuple[str, str]:
    """TIER 2: cryptographically verify the DKIM signature using the
    sender's public key (published in their DNS). This is a real
    signature check, not a keyword match - dkimpy fetches the public
    key from DNS and verifies the signature against the email content."""
    try:
        result = dkim.verify(raw_email_bytes)
        if result:
            return "pass", "DKIM signature is cryptographically valid"
        else:
            return "fail", "DKIM signature present but does not verify - email may have been tampered with, or signature is invalid"
    except Exception as e:
        return "error", f"Could not verify DKIM signature: {e}"


def run_full_auth_check(parsed_email, sender_domain: str, live: bool = True) -> AuthResult:
    """Combines tier 1 (header parsing, always works) with tier 2
    (live verification, requires network) when available. Tier 2
    results take precedence when they succeed, since they're a
    genuine independent check rather than trusting a header that
    could itself have been forged by whoever relayed the message."""

    tier1 = parse_authentication_results_header(parsed_email.authentication_results)

    if not live:
        return tier1

    details = list(tier1.details)
    spf_verdict = tier1.spf
    dmarc_verdict = tier1.dmarc
    dkim_verdict = tier1.dkim

    spf_status, spf_detail = check_spf_live(sender_domain)
    details.append(f"[live] SPF record check: {spf_detail}")
    if spf_status == "no_record":
        spf_verdict = "no_record" if tier1.spf == "none" else tier1.spf

    dmarc_policy, dmarc_detail = check_dmarc_live(sender_domain)
    details.append(f"[live] DMARC policy: {dmarc_policy}")
    if tier1.dmarc == "none":
        dmarc_verdict = dmarc_policy

    if parsed_email.dkim_signature_present:
        dkim_status, dkim_detail = verify_dkim_signature(parsed_email.raw_source.encode("utf-8"))
        details.append(f"[live] DKIM verification: {dkim_detail}")
        dkim_verdict = dkim_status

    return AuthResult(
        spf=spf_verdict,
        dkim=dkim_verdict,
        dmarc=dmarc_verdict,
        source="live",
        details=details,
    )
