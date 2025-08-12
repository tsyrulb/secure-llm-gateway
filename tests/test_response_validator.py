import pytest

@pytest.mark.parametrize("secret_content, expected_redaction", [
    ("The key is sk-THISISAREALLYLONGSECRETKEYSHOULDBEREDACTED", "The key is [[secret]]"),
    ("my api_key = 'ABC123XYZ789THISISVERYSECRET'", "my [[secret]]"),
    ("Use this token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.very-long-signature", "Use this token: [[secret]]"),
    ("The AWS key is AKIAIOSFODNN7EXAMPLE", "The AWS key is [[secret]]"),
])
def test_secret_redaction(client, secret_content, expected_redaction):
    """
    Verifies that various secret patterns are redacted from the LLM response.
    The stub provider echoes the user's content, which allows us to test the response validator.
    """
    payload = {
        "model": "stub",
        "messages": [{"role": "user", "content": secret_content}],
    }
    r = client.post("/v1/chat/completions",
                    headers={"Authorization": "Bearer dev-token"},
                    json=payload)
    assert r.status_code == 200
    response_data = r.json()
    
    # The stub provider prepends a prefix, so we check if the expected redaction is 'in' the answer.
    assert expected_redaction in response_data["answer"]
    
    # Also verify that the original secret is NOT in the answer.
    # This is a simple way to get the secret part for the test cases above.
    original_secret_part = secret_content.split(" ")[-1]
    assert original_secret_part not in response_data["answer"]


@pytest.mark.parametrize("pii_content, expected_redaction", [
    ("My email is test.user@example.com.", "My email is [[pii]]."),
    ("You can reach me at 555-123-4567.", "You can reach me at [[pii]]."),
    ("Call (123) 456-7890 for help.", "Call [[pii]] for help."),
    ("Contact support@company.co.uk for more info.", "Contact [[pii]] for more info."),
    ("Phone: +1 415 555 2671", "Phone: [[pii]]"),
])
def test_pii_redaction(client, pii_content, expected_redaction):
    """
    Verifies that various PII patterns (emails, phone numbers) are redacted.
    """
    payload = {
        "model": "stub",
        "messages": [{"role": "user", "content": pii_content}],
    }
    r = client.post("/v1/chat/completions",
                    headers={"Authorization": "Bearer dev-token"},
                    json=payload)
    assert r.status_code == 200
    response_data = r.json()

    assert expected_redaction in response_data["answer"]
    
    # Verify the original PII is not in the response.
    original_pii_part = pii_content.split(" ")[-1].replace('.', '')
    assert original_pii_part not in response_data["answer"]


def test_no_redaction_for_safe_content(client):
    """
    Ensures that the validator does not incorrectly redact safe content.
    """
    safe_content = "This is a perfectly safe sentence with no secrets or PII. My favorite number is 12345."
    payload = {
        "model": "stub",
        "messages": [{"role": "user", "content": safe_content}],
    }
    r = client.post("/v1/chat/completions",
                    headers={"Authorization": "Bearer dev-token"},
                    json=payload)
    assert r.status_code == 200
    response_data = r.json()

    # Check that no redaction placeholders are present.
    assert "[[secret]]" not in response_data["answer"]
    assert "[[pii]]" not in response_data["answer"]
    
    # Check that the original content is still present.
    assert safe_content in response_data["answer"]
