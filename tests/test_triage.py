import asyncio
from email.message import EmailMessage
from fastapi.testclient import TestClient
import main


def test_unknown_is_not_clean():
    assert main.stats_verdict({}) == 'unknown'
    assert main.stats_verdict({'timeout': 9}) == 'unknown'
    assert main.stats_verdict({'undetected': 60}) == 'clean'
    assert main.compute_overall_verdict({'status': 'error'}, {'status': 'not_found'}, {}, {}) == 'clean'  # V1 kurali: kanit yoksa temiz


def test_phishing_evidence_and_official_domains():
    assert not main.phishing_findings('https://accounts.google.com/login')
    assert not main.phishing_findings('https://paypal.com/')
    assert any(f['code'] == 'brand_similarity' for f in main.phishing_findings('https://paypa1.com/'))
    assert any(f['code'] == 'brand_subdomain' for f in main.phishing_findings('https://paypal.com.attacker.co.uk/'))
    assert any(f['code'] == 'userinfo' for f in main.phishing_findings('https://bank.example@other.test/'))
    assert main.extract_domain('https://bank.example@other.test:443/x') == 'other.test'
    assert main.extract_domain('http://[2001:db8::1]:80/') == '2001:db8::1'


def test_batch_dedup_validation_priority(monkeypatch):
    calls = []

    async def fake(url):
        calls.append(url)
        return {'url': url, 'verdict': 'unknown', 'priority': 'needs_data', 'findings': []}

    monkeypatch.setattr(main, 'check_url_intelligence', fake)
    with TestClient(main.app) as client:
        r = client.post('/analyze/urls', json={'urls': ['https://example.com', 'https://example.com/', 'bad']})
        assert r.status_code == 200
        assert len(calls) == 1
        assert r.json()['duplicates_removed'] == 1
        assert len(r.json()['errors']) == 1
        assert client.post('/analyze/urls', json={'urls': ['https://example.com'] * 11}).status_code == 422


def test_hash_report_accepts_large_metadata_and_unknown(monkeypatch):
    async def fake(client, kind, identifier):
        assert kind == 'files'
        assert identifier == 'a' * 64
        return {'status': 'not_found', 'verdict': 'unknown', 'stats': {}, 'detail': 'Not found'}

    monkeypatch.setattr(main, 'cached_vt_report', fake)
    with TestClient(main.app) as client:
        r = client.post('/analyze/hash', json={'sha256': 'A' * 64, 'file_size': 800 * 1024**2})
        assert r.status_code == 200
        assert r.json()['verdict'] == 'unknown'
        assert r.json()['file_size'] == 800 * 1024**2
        assert client.post('/analyze/hash', json={'sha256': 'invalid'}).status_code == 422


def test_vt_budget_and_cache(monkeypatch):
    main._vt_hits.clear()
    main._vt_daily.clear()
    main._report_cache.clear()
    monkeypatch.setattr(main, 'VT_API_KEY', 'dummy')

    class Resp:
        status_code = 404

    class Client:
        calls = 0

        async def get(self, *args, **kwargs):
            self.calls += 1
            return Resp()

    async def run():
        c = Client()
        a = await main.cached_vt_report(c, 'files', 'a')
        b = await main.cached_vt_report(c, 'files', 'a')
        assert a['verdict'] == 'unknown' and b['cached']
        assert c.calls == 1
        for i in range(3):
            await main.cached_vt_report(c, 'files', str(i))
        limited = await main.cached_vt_report(c, 'files', 'fifth')
        assert limited['status'] == 'rate_limited' and c.calls == 4

    try:
        asyncio.run(run())
    finally:
        main._vt_hits.clear()
        main._vt_daily.clear()
        main._report_cache.clear()


def test_imap_readonly_peek(monkeypatch):
    msg = EmailMessage()
    msg['Subject'] = 'test'
    msg.set_content('https://example.com')

    class Mail:
        def __init__(self, *a, **kw):
            assert kw['timeout'] == 15

        def login(self, *a): pass

        def select(self, folder, readonly):
            assert readonly is True

        def search(self, *a):
            return 'OK', [b'1']

        def fetch(self, num, part):
            assert part == '(BODY.PEEK[])'
            return 'OK', [(b'1', msg.as_bytes())]

        def logout(self): pass

    monkeypatch.setattr(main.imaplib, 'IMAP4_SSL', Mail)
    assert main.fetch_imap_mails_sync()[0]['subject'] == 'test'


def test_dashboard_and_assets_exist():
    with TestClient(main.app) as client:
        h = client.get('/').text
        assert 'id="dashboard"' in h
        assert 'id="ai-input"' in h  # AI asistan UI korundu
        for path in ['/static/app.js', '/static/hash-worker.js', '/static/styles.css']:
            assert client.get(path).status_code == 200
