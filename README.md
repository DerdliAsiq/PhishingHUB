# PhishingHUB — Passive Security Workspace

Şüpheli URL, dosya ve IMAP mailbox'ını izole analiz eden FastAPI + tek sayfa web uygulaması.

## Özellikler
- **URL Scan:** VirusTotal (submit + poll + fallback lookup), URLhaus, AbuseIPDB, Pulsedive — paralel `httpx`, structured `verdict` (malicious / suspicious / clean / unknown).
- **File Upload:** Chunk-stream SHA-256, 50MB limit (`413`), VT hash lookup.
- **IMAP Inbox:** UNSEEN mailler (max 10), `text/plain` + `text/html` link çıkarımı (max 10/mail), attachment SHA-256 + VT lookup (max 5/mail).
- **Güvenlik:** Secret'lar sadece env'den (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `PULSEDIVE_API_KEY`, `IMAP_*`, `OPENROUTER_API_KEY`), frontend `escapeHtml` (XSS koruması), `HttpUrl` validasyonu, private-IP skip.
- **AI Asistan (MOD-02):** Son tarama sonucunu OpenRouter free modele sorar, verdict'i Türkçe yorumlar. Context özetlenir (~4KB), ham mail/dosya içeriği gönderilmez, dakikada 10 mesaj/IP limiti.

## Kurulum
```bash
pip install -r requirements.txt
cp .env.example .env  # gerçek key'leri doldur (Render'da Environment Variables)
uvicorn main:app --host 0.0.0.0 --port 8000
```

Render: Dashboard → Environment → `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `PULSEDIVE_API_KEY`, `IMAP_SERVER`, `IMAP_USER`, `IMAP_PASS`, `OPENROUTER_API_KEY`, `AI_MODEL` ekle. Kodda hardcoded key yoktur. Secret'leri chat'e/sohbete yapıştırma, `.env.example`'a değer yazma.

## Endpoint'ler
| Method | Path | Açıklama |
|---|---|---|
| `GET` | `/` | `index.html` |
| `POST` | `/analyze/url` | `{url}` → `{verdict, virustotal, urlhaus, abuseipdb, pulsedive}` |
| `POST` | `/analyze/file` | multipart `file` → `{file_hash, stats, action}` |
| `POST` | `/analyze/imap` | UNSEEN tara → `{results[{subject, from, urls_found, attachments}]}` |
| `POST` | `/analyze/ai-chat` | `{message, context}` → `{reply, model}` (OpenRouter, key yoksa `503`) |
| `GET` | `/health` | `{vt_configured, ai_configured, ai_model}` (değerler asla dönülmez) |

## Test
```bash
pytest -q
```

## Limitler
- Dosya/attachment: 50MB, mail başına 10 URL / 5 ek, IMAP timeout 40sn.
- VT kota (429) / geçersiz key (401) → `503` ile açık mesaj.
