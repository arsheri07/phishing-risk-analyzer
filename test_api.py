from app import app


def _email(body="Hello"):
    return (
        "From: Billing <billing@example.com>\n"
        "Authentication-Results: mx.example; spf=pass dkim=pass dmarc=pass\n"
        "Subject: Account update\n\n" + body
    )


def test_email_api_returns_explainable_result():
    response = app.test_client().post("/api/analyze/email", json={"raw_email": _email()})
    data = response.get_json()
    assert response.status_code == 200
    assert data["verdict"] == "SAFE"
    assert data["email_summary"]["sender_domain"] == "example.com"


def test_all_local_analysis_apis_accept_representative_samples():
    client = app.test_client()
    cases = [
        ("/api/analyze/sms", {"message": "Your package is on hold. Forward this code: http://paypa1.example"}),
        ("/api/analyze/phone", {"transcript": "This is the IRS. Pay with a gift card immediately."}),
        ("/api/analyze/app", {"app_name": "Torch", "developer_name": "App1234", "description": "Simple flashlight app with guaranteed profit", "permissions": "Camera, Contacts"}),
    ]
    for path, payload in cases:
        response = client.post(path, json=payload)
        assert response.status_code == 200
        assert response.get_json()["verdict"] == "DANGEROUS"


def test_phone_api_normalizes_an_unformatted_caller_number():
    response = app.test_client().post("/api/analyze/phone", json={
        "phone_number": "2025550199",
        "transcript": "Hi, this is Sarah confirming your dentist appointment.",
    })
    assert response.status_code == 200
    assert response.get_json()["summary"]["phone_number"] == "+1-202-555-0199"


def test_website_api_rejects_internal_targets_before_fetching():
    response = app.test_client().post("/api/analyze/website", json={"url": "http://127.0.0.1/admin"})
    assert response.status_code == 400
    assert "publicly reachable" in response.get_json()["error"]
