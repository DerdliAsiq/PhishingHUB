import main
from fastapi.testclient import TestClient


def _client():
    return TestClient(main.app, raise_server_exceptions=False)


def test_ai_context_trim():
    big = {"type": "url", "url_scanned": "https://x.com/" + "a" * 100,
           "verdict": "clean", "virustotal": {"verdict": "clean", "stats": {}},
           "urlhaus": {"status": "clean"}, "abuseipdb": {"status": "ok"},
           "pulsedive": {"status": "low"}}
    # şişir
    big["url_scanned"] = "https://x.com/" + "a" * 6000
    s = main.build_ai_context_summary(big)
    assert len(s) <= main.AI_MAX_CONTEXT_CHARS + 20
    assert "kırpıldı" in s


def test_ai_no_key_503(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(main, "OPENROUTER_API_KEY", None)
    main._ai_hits.clear()
    r = _client().post("/analyze/ai-chat", json={"message": "merhaba"})
    assert r.status_code == 503


def test_ai_success_mock(monkeypatch):
    async def fake_call(text: str) -> str:
        assert "<scan>" in text
        return "mock cevap"
    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy")
    monkeypatch.setattr(main, "OPENROUTER_API_KEY", "dummy")
    monkeypatch.setattr(main, "call_openrouter", fake_call)
    main._ai_hits.clear()
    c = _client()
    r = c.post("/analyze/ai-chat", json={
        "message": "bu ne demek?",
        "context": {"type": "url", "url_scanned": "https://x.com",
                    "verdict": "clean", "virustotal": {}, "urlhaus": {},
                    "abuseipdb": {}, "pulsedive": {}},
    })
    assert r.status_code == 200
    assert r.json()["reply"] == "mock cevap"


def test_ai_rate_limit(monkeypatch):
    async def fake_call(text: str) -> str:
        return "ok"
    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy")
    monkeypatch.setattr(main, "OPENROUTER_API_KEY", "dummy")
    monkeypatch.setattr(main, "call_openrouter", fake_call)
    monkeypatch.setattr(main, "AI_RATE_LIMIT", 2)
    main._ai_hits.clear()
    c = _client()
    assert c.post("/analyze/ai-chat", json={"message": "1"}).status_code == 200
    assert c.post("/analyze/ai-chat", json={"message": "2"}).status_code == 200
    assert c.post("/analyze/ai-chat", json={"message": "3"}).status_code == 429
    monkeypatch.setattr(main, "AI_RATE_LIMIT", 10)


def test_ai_validation():
    main._ai_hits.clear()
    r = _client().post("/analyze/ai-chat", json={"message": ""})
    assert r.status_code == 422
