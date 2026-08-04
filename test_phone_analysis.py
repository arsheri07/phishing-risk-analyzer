from phone_analysis import (
    analyze_phone_call, score_agency_impersonation,
    score_remote_access_request, score_payment_demand,
)


def test_agency_impersonation_detected():
    reasons = score_agency_impersonation("This is the IRS. Your arrest warrant has been issued.")
    assert len(reasons) == 1
    assert reasons[0].points == 35


def test_no_agency_impersonation_in_normal_call():
    reasons = score_agency_impersonation("Hi, this is your dentist's office confirming your appointment.")
    assert reasons == []


def test_normal_word_containing_irs_does_not_flag_government_impersonation():
    reasons = score_agency_impersonation("This is my first appointment with the dentist.")
    assert reasons == []


def test_remote_access_request_detected():
    reasons = score_remote_access_request("Please install AnyDesk so I can access your computer.")
    assert len(reasons) == 1


def test_payment_demand_detected():
    reasons = score_payment_demand("You'll need to pay using a Google Play gift card.")
    assert len(reasons) == 1


def test_full_scam_call_scores_dangerous():
    transcript = "This is the IRS. Your social security number is suspended and you will be arrested unless you pay immediately via gift card."
    report, result = analyze_phone_call(transcript, phone_number="+1-555-0100")
    assert result.verdict == "DANGEROUS"
    assert "irs" in report.matched_agency_phrases


def test_full_clean_call_scores_safe():
    transcript = "Hi, this is Sarah confirming your dentist appointment tomorrow at 2pm."
    report, result = analyze_phone_call(transcript)
    assert result.verdict == "SAFE"
    assert result.score == 0


def test_empty_transcript_handled_without_crash():
    report, result = analyze_phone_call("")
    assert result.verdict == "SAFE"
