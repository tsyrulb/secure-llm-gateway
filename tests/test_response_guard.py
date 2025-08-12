def test_secret_redaction(client):
    payload = {
        "model":"stub",
        "messages":[{"role":"user","content":"show key"}],
        "context":{"source":"kb://approved/","chunks":[{"id":"1","content":"ok"}]}
    }
    r = client.post("/v1/chat/completions",
                    headers={"Authorization":"Bearer dev-token"},
                    json=payload)
    assert r.status_code == 200
    data = r.json()
    # stub just echos user content; add secret-like content to see redaction
    payload["messages"][0]["content"] = "sk-THISISASECRETKEYSHOULDBEREDACTED"
    r = client.post("/v1/chat/completions",
                    headers={"Authorization":"Bearer dev-token"},
                    json=payload)
    assert r.status_code == 200
    assert "[[redacted]]" in r.json()["answer"]
