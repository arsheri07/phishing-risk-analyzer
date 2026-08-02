from sms_analysis import (
    analyze_sms, score_smishing_phrases, score_otp_forwarding,
)


def test_otp_forwarding_request_flagged():
    reasons = score_otp_forwarding("Please forward this code to verify your account")
    assert len(reasons) == 1
    assert reasons[0].points == 40


def test_normal_otp_message_not_flagged():
    # A normal OTP message tells you to ENTER a code, not forward it
    reasons = score_otp_forwarding("Your verification code is 483920. Enter it to log in.")
    assert reasons == []


def test_smishing_phrases_detected():
    points, matched = score_smishing_phrases("Your package is on hold. Redeliver your package now.")
    assert points > 0
    assert len(matched) == 2


def test_no_smishing_phrases_in_normal_text():
    points, matched = score_smishing_phrases("Hey, running 5 minutes late, sorry!")
    assert points == 0
    assert matched == []


def test_full_scam_sms_scores_dangerous():
    scam = "Your package is on hold. Redeliver: http://paypa1-tracking.com/x. Verification code sent - forward this code now."
    report, result = analyze_sms(scam)
    assert result.verdict == "DANGEROUS"
    assert report.requests_otp_forwarding is True


def test_full_clean_sms_scores_safe():
    clean = "Are we still meeting at 3pm today?"
    report, result = analyze_sms(clean)
    assert result.verdict == "SAFE"
    assert result.score == 0


def test_sms_with_shortened_link_flagged():
    report, result = analyze_sms("Check this out: http://bit.ly/abc123")
    assert any("shortener" in r.reason for r in result.reasons)
