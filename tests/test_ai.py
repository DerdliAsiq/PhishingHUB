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
        return "Verdict: temiz\nRISK: 12"
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
    assert r.json()["reply"] == "Verdict: temiz"
    assert r.json()["risk"] == 12


def test_ai_reply_parse():
    clean, risk = main.parse_ai_reply("kısa yorum\nRISK: 85")
    assert clean == "kısa yorum"
    assert risk == 85
    clean2, risk2 = main.parse_ai_reply("RISK yok")
    assert risk2 is None
    clean3, risk3 = main.parse_ai_reply("x\nRISK: 250")
    assert risk3 == 100


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


def test_extract_reply_variants():
    assert main.extract_reply_text({"choices": [{"message": {"content": "  merhaba  "}}]}) == "merhaba"
    assert main.extract_reply_text({"choices": [{"message": {"content": None, "reasoning": "akıl yürütme"}}]}) == "akıl yürütme"
    assert main.extract_reply_text({"choices": [{"message": {"content": [{"type": "text", "text": "blok"}]}}]}) == "blok"
    assert main.extract_reply_text({"choices": []}) is None
    assert main.extract_reply_text({}) is None


def test_openrouter_fallback(monkeypatch):
    import asyncio

    class Resp:
        def __init__(self, status, payload):
            self.status_code = status
            self._p = payload

        def json(self):
            return self._p

    class Client:
        responses = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return Client.responses.pop(0)

    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy")
    monkeypatch.setattr(main, "OPENROUTER_API_KEY", "dummy")
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **k: Client())
    Client.responses = [
        Resp(200, {"choices": [{"message": {"content": None}}]}),
        Resp(200, {"choices": [{"message": {"content": "fallback ok\nRISK: 5"}}]}),
    ]
    out = asyncio.run(main.call_openrouter("test"))
    assert out == "fallback ok\nRISK: 5"


def test_openrouter_error_in_200(monkeypatch):
    import asyncio
    from fastapi import HTTPException

    class Resp:
        status_code = 200

        def json(self):
            return {"error": {"message": "No endpoints found"}}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return Resp()

    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy")
    monkeypatch.setattr(main, "OPENROUTER_API_KEY", "dummy")
    monkeypatch.delenv("AI_FALLBACK_MODEL", raising=False)
    monkeypatch.setattr(main, "AI_FALLBACK_MODEL", "")
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **k: Client())
    try:
        asyncio.run(main.call_openrouter("test"))
        assert False, "hata bekleniyordu"
    except HTTPException as e:
        assert "No endpoints found" in e.detail
