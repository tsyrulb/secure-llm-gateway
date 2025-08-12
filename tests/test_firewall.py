def test_rejects_disallowed_model(client, monkeypatch):
    monkeypatch.setenv("ALLOWED_MODELS", "stub")
    resp = client.post("/v1/chat/completions",
        headers={"Authorization":"Bearer dev-token"},
        json={"model":"openai:gpt-4o","messages":[{"role":"user","content":"hi"}]}
    )
    assert resp.status_code == 403

def test_context_allowlist(client, monkeypatch):
    monkeypatch.setenv("ALLOWED_CONTEXT_ORIGINS", "kb://approved/")
    payload = {
        "model":"stub",
        "messages":[{"role":"user","content":"x"}],
        "context":{"source":"kb://approved/file.md","chunks":[{"id":"1","content":"ok"}]}
    }
    r = client.post("/v1/chat/completions", headers={"Authorization":"Bearer dev-token"}, json=payload)
    assert r.status_code == 200
    # now disallow
    payload["context"]["source"] = "kb://evil/file.md"
    r = client.post("/v1/chat/completions", headers={"Authorization":"Bearer dev-token"}, json=payload)
    assert r.status_code in (400,403)
