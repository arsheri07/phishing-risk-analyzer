"""
app.py
------
Scam Shield - unified scam detection platform.

Two analysis modules sharing one scoring engine:
- Email tab: SPF/DKIM/DMARC verification, lookalike-domain detection,
  urgency language scoring (originally "Email Forensics")
- Website tab: domain age, SSL validity, redirect chains, scam payment
  language, plus the same lookalike-domain detection reused from email

Run locally: python3 app.py
Then visit http://localhost:5000
"""

import os
from flask import Flask, request, jsonify, render_template
from dataclasses import asdict

from email_parser import parse_email, get_sender_domain
from auth_checks import run_full_auth_check
from link_analysis import analyze_links
from scoring import analyze_email
from website_analysis import analyze_website
from sms_analysis import analyze_sms
from phone_analysis import analyze_phone_call
from app_listing_analysis import analyze_app_listing

app = Flask(__name__)

MAX_EMAIL_SIZE = 500_000


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze/email", methods=["POST"])
def api_analyze_email():
    data = request.get_json(silent=True) or {}
    raw_email = data.get("raw_email", "")

    if not raw_email or not raw_email.strip():
        return jsonify({"error": "No email content provided"}), 400
    if len(raw_email) > MAX_EMAIL_SIZE:
        return jsonify({"error": "Email content too large"}), 400

    live = data.get("live_checks", False)

    try:
        parsed = parse_email(raw_email)
    except Exception as e:
        return jsonify({"error": f"Could not parse email: {e}"}), 400

    domain = get_sender_domain(parsed.from_address)

    try:
        auth_result = run_full_auth_check(parsed, domain, live=live)
    except Exception as e:
        return jsonify({"error": f"Authentication check failed: {e}"}), 500

    link_findings = analyze_links(parsed.body_text, parsed.body_html)
    result = analyze_email(parsed, auth_result, link_findings)

    return jsonify({
        "verdict": result.verdict,
        "score": result.score,
        "reasons": [asdict(r) for r in sorted(result.reasons, key=lambda r: -r.points)],
        "email_summary": {
            "from_address": parsed.from_address,
            "from_display_name": parsed.from_display_name,
            "reply_to": parsed.reply_to,
            "subject": parsed.subject,
            "sender_domain": domain,
        },
        "auth": {
            "spf": auth_result.spf, "dkim": auth_result.dkim, "dmarc": auth_result.dmarc,
            "source": auth_result.source, "details": auth_result.details,
        },
        "links": [
            {
                "url": f.url, "domain": f.domain,
                "is_typosquat": f.is_typosquat, "typosquat_target": f.typosquat_target,
                "is_combosquat": f.is_combosquat, "combosquat_target": f.combosquat_target,
                "is_ip_address": f.is_ip_address, "uses_url_shortener": f.uses_url_shortener,
            }
            for f in link_findings
        ],
    })


@app.route("/api/analyze/website", methods=["POST"])
def api_analyze_website():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    try:
        report, result = analyze_website(url)
    except Exception as e:
        return jsonify({"error": f"Could not analyze site: {e}"}), 500

    return jsonify({
        "verdict": result.verdict,
        "score": result.score,
        "reasons": [asdict(r) for r in sorted(result.reasons, key=lambda r: -r.points)],
        "site_summary": {
            "url": report.url,
            "domain": report.domain,
            "final_url": report.final_url,
            "domain_age_days": report.domain_age_days,
            "has_valid_ssl": report.has_valid_ssl,
            "redirect_count": len(report.redirect_chain),
            "fetch_error": report.fetch_error,
        },
    })


@app.route("/api/analyze/sms", methods=["POST"])
def api_analyze_sms():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"error": "No message provided"}), 400
    if len(message) > 5000:
        return jsonify({"error": "Message too long"}), 400

    try:
        report, result = analyze_sms(message)
    except Exception as e:
        return jsonify({"error": f"Could not analyze message: {e}"}), 500

    return jsonify({
        "verdict": result.verdict,
        "score": result.score,
        "reasons": [asdict(r) for r in sorted(result.reasons, key=lambda r: -r.points)],
        "summary": {
            "requests_otp_forwarding": report.requests_otp_forwarding,
            "link_count": len(report.links),
        },
    })


@app.route("/api/analyze/phone", methods=["POST"])
def api_analyze_phone():
    data = request.get_json(silent=True) or {}
    transcript = data.get("transcript", "").strip()
    phone_number = data.get("phone_number", "").strip()

    if not transcript:
        return jsonify({"error": "No transcript provided"}), 400
    if len(transcript) > 10000:
        return jsonify({"error": "Transcript too long"}), 400

    try:
        report, result = analyze_phone_call(transcript, phone_number)
    except Exception as e:
        return jsonify({"error": f"Could not analyze call: {e}"}), 500

    return jsonify({
        "verdict": result.verdict,
        "score": result.score,
        "reasons": [asdict(r) for r in sorted(result.reasons, key=lambda r: -r.points)],
        "summary": {
            "phone_number": report.phone_number,
            "matched_agency_phrases": report.matched_agency_phrases,
            "matched_remote_access": report.matched_remote_access,
        },
    })


@app.route("/api/analyze/app", methods=["POST"])
def api_analyze_app():
    data = request.get_json(silent=True) or {}
    app_name = data.get("app_name", "").strip()
    developer_name = data.get("developer_name", "").strip()
    description = data.get("description", "").strip()
    permissions_text = data.get("permissions", "").strip()

    if not description:
        return jsonify({"error": "App description is required"}), 400

    try:
        report, result = analyze_app_listing(app_name, developer_name, description, permissions_text)
    except Exception as e:
        return jsonify({"error": f"Could not analyze app listing: {e}"}), 500

    return jsonify({
        "verdict": result.verdict,
        "score": result.score,
        "reasons": [asdict(r) for r in sorted(result.reasons, key=lambda r: -r.points)],
        "summary": {
            "app_name": report.app_name,
            "developer_name": report.developer_name,
            "permissions": report.permissions,
            "generic_developer_name": report.generic_developer_name,
        },
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
