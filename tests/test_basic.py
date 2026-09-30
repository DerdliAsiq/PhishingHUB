import hashlib
import main


def test_normalize_url():
    assert main.normalize_url("www.example.com/a") == "https://www.example.com/a"
    assert main.normalize_url("https://example.com/a.,") == "https://example.com/a"
    assert main.normalize_url("not a url") is None


def test_extract_urls_plain_and_html():
    urls = main.extract_urls_from_blob(
        "bak https://example.com/x",
        '<a href="http://evil.test/phish">tıkla</a>',
    )
    assert "https://example.com/x" in urls
    assert "http://evil.test/phish" in urls


def test_private_ip_skipped():
    assert main.is_private_ip("127.0.0.1") is True
    assert main.is_private_ip("192.168.1.1") is True
    assert main.is_private_ip("8.8.8.8") is False


def test_verdict_logic():
    v = main.compute_overall_verdict(
        {"stats": {"malicious": 2}, "status": "completed"},
        {"status": "clean"},
        {"score": 0},
        {"risk": "low"},
    )
    assert v == "malicious"
    v2 = main.compute_overall_verdict(
        {"stats": {"malicious": 0, "suspicious": 0}, "status": "completed"},
        {"status": "clean"},
        {"score": 0},
        {"risk": "low"},
    )
    assert v2 == "clean"


def test_parse_email_html_and_attachment():
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = "Fatura"
    msg["From"] = "a@b.com"
    msg.set_content("Merhaba https://example.com/fatura")
    msg.add_alternative('<a href="http://evil.test/x">tıkla</a>', subtype="html")
    data = b"x" * 10
    msg.add_attachment(data, maintype="application", subtype="octet-stream", filename="fatura.pdf")
    raw = msg.as_bytes()
    parsed = main.parse_email_bytes(raw)
    assert "https://example.com/fatura" in parsed["urls"]
    assert "http://evil.test/x" in parsed["urls"]
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["sha256"] == hashlib.sha256(data).hexdigest()
