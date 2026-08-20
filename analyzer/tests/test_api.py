from fastapi.testclient import TestClient

from app.main import app


def test_contextual_analysis_returns_fingerprint_not_value():
    with TestClient(app) as client:
        body = client.post("/v1/analyze", json={"text": "Call me at +91 9876543210"}).json()
        assert body["findings"][0]["type"] == "phone"
        assert "9876543210" not in str(body)
