# tests/test_response_validator.py
import pytest
from api.main import app
from api.config import get_settings

# Provide a default settings override for all tests in this file
@pytest.fixture(autouse=True)
def override_settings_for_validator():
    app.dependency_overrides[get_settings] = get_settings
    yield
    app.dependency_overrides.clear()

@pytest.mark.parametrize("secret_content, original_secret", [
    ("The key is sk_THISISAREALLYLONGSECRETKEYSHOULDBEREDACTED", "sk_THISISAREALLYLONGSECRETKEYSHOULDBEREDACTED"),
    ("my api_key = 'ABC123XYZ789THISISVERYSECRET'", "api_key = 'ABC123XYZ789THISISVERYSECRET'"),
    ("Use this token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.very-long-signature", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.very-long-signature"),
    ("The AWS key is AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
])
def test_secret_redaction(client, secret_content, original_secret):
    """
    Verifies that various secret patterns are redacted from the LLM response.
    """
    payload = {"model": "stub", "messages": [{"role": "user", "content": secret_content}]}
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer dev-token"}, json=payload)
    assert r.status_code == 200
    response_data = r.json()
    
    assert "[[secret]]" in response_data["answer"]
    assert original_secret not in response_data["answer"]

@pytest.mark.parametrize("pii_content, original_pii", [
    ("My email is test.user@example.com.", "test.user@example.com"),
    ("You can reach me at 555-123-4567.", "555-123-4567"),
    ("Call (123) 456-7890 for help.", "(123) 456-7890"),
    ("Contact support@company.co.uk for more info.", "support@company.co.uk"),
    ("Phone: +1 415 555 2671", "+1 415 555 2671"),
])
def test_pii_redaction(client, pii_content, original_pii):
    """
    Verifies that various PII patterns (emails, phone numbers) are redacted.
    """
    payload = {"model": "stub", "messages": [{"role": "user", "content": pii_content}]}
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer dev-token"}, json=payload)
    assert r.status_code == 200
    response_data = r.json()

    assert "[[pii]]" in response_data["answer"]
    assert original_pii not in response_data["answer"]

def test_no_redaction_for_safe_content(client):
    """
    Ensures that the validator does not incorrectly redact safe content.
    """
    safe_content = "This is a perfectly safe sentence with no secrets or PII. My favorite number is 12345."
    payload = {"model": "stub", "messages": [{"role": "user", "content": safe_content}]}
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer dev-token"}, json=payload)
    assert r.status_code == 200
    response_data = r.json()

    assert "[[secret]]" not in response_data["answer"]
    assert "[[pii]]" not in response_data["answer"]
    assert "stub:dev-tenant" in response_data["answer"]