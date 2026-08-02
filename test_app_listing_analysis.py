from app_listing_analysis import (
    analyze_app_listing, score_too_good_to_be_true,
    score_permission_mismatch, score_generic_developer_name,
)


def test_too_good_to_be_true_detected():
    reasons = score_too_good_to_be_true("Guaranteed profit every single day, 100% guaranteed!")
    assert len(reasons) == 1


def test_normal_description_not_flagged():
    reasons = score_too_good_to_be_true("A simple app to track your daily water intake.")
    assert reasons == []


def test_permission_mismatch_detected_for_flashlight_app():
    reasons = score_permission_mismatch(
        "Simple flashlight app, just tap to turn on the light.",
        ["Camera", "Contacts", "SMS", "Location"]
    )
    assert len(reasons) == 1
    assert reasons[0].points == 40


def test_flashlight_app_with_reasonable_permissions_not_flagged():
    reasons = score_permission_mismatch(
        "Simple flashlight app, just tap to turn on the light.",
        ["Camera"]  # flashlight legitimately needs camera flash access
    )
    assert reasons == []


def test_generic_developer_name_flagged():
    reasons = score_generic_developer_name("App1234")
    assert len(reasons) == 1


def test_real_company_name_not_flagged():
    reasons = score_generic_developer_name("Acme Software Inc.")
    assert reasons == []


def test_full_scam_app_scores_dangerous():
    report, result = analyze_app_listing(
        app_name="Super Flashlight Pro",
        developer_name="App9921",
        description="Simple flashlight app. Also guaranteed passive income guaranteed!",
        permissions_text="Camera, Contacts, SMS, Microphone, Location",
    )
    assert result.verdict == "DANGEROUS"
    assert report.permission_mismatch is True


def test_full_clean_app_scores_safe():
    report, result = analyze_app_listing(
        app_name="Notes",
        developer_name="Acme Software Inc.",
        description="A simple note-taking app.",
        permissions_text="Storage",
    )
    assert result.verdict == "SAFE"
    assert result.score == 0
