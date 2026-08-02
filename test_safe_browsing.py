import os
from unittest.mock import patch
import requests


def test_not_configured_when_no_api_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    from safe_browsing import is_configured, check_url
    assert is_configured() is False
    result = check_url("http://example.com")
    assert result["checked"] is False
    assert result["error"] == "not_configured"


def test_check_url_never_raises_on_network_failure(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key-abc")
    from safe_browsing import check_url
    with patch("safe_browsing.requests.post") as mock_post:
        mock_post.side_effect = requests.exceptions.Timeout("timed out")
        result = check_url("http://example.com")
        assert result["checked"] is False
        assert result["is_threat"] is False


def test_api_key_never_appears_in_error_message(monkeypatch):
    secret_key = "SECRET_KEY_SHOULD_NOT_LEAK_12345"
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", secret_key)
    from safe_browsing import check_url
    with patch("safe_browsing.requests.post") as mock_post:
        mock_post.side_effect = requests.exceptions.RequestException(f"failed with key={secret_key}")
        result = check_url("http://example.com")
        assert secret_key not in result["error"]
        assert "[REDACTED]" in result["error"]


def test_threat_match_flagged_correctly(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key-abc")
    from safe_browsing import check_url
    with patch("safe_browsing.requests.post") as mock_post:
        mock_response = mock_post.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "matches": [{"threatType": "SOCIAL_ENGINEERING"}]
        }
        result = check_url("http://known-bad-site.example")
        assert result["checked"] is True
        assert result["is_threat"] is True
        assert "SOCIAL_ENGINEERING" in result["threat_types"]


def test_clean_url_not_flagged(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key-abc")
    from safe_browsing import check_url
    with patch("safe_browsing.requests.post") as mock_post:
        mock_response = mock_post.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"matches": []}
        result = check_url("http://example.com")
        assert result["checked"] is True
        assert result["is_threat"] is False
