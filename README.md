# PhishingHUB — Passive Security Workspace

Şüpheli URL, dosya ve IMAP mailbox'ını izole analiz eden FastAPI + tek sayfa web uygulaması.

## Özellikler
- **URL Scan:** VirusTotal (submit + poll + fallback lookup), URLhaus, AbuseIPDB, Pulsedive — paralel `httpx`, structured `verdict` (malicious / suspicious / clean / unknown).
- **File Upload:** Chunk-stream SHA-256, 50MB limit (`413`), VT hash lookup.
- **IMAP Inbox:** UNSEEN mailler (max 10), `text/plain` + `text/html` link çıkarımı (max 10/mail), attachment SHA-256 + VT lookup (max 5/mail).
- **Güvenlik:** Secret'lar sadece env'den (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `PULSEDIVE_API_KEY`, `IMAP_*`), frontend `escapeHtml` (XSS koruması), `HttpUrl` validasyonu, private-IP skip.

## Kurulum
```bash
pip install -r requirements.txt
cp .env.example .env  # gerçek key'leri doldur (Render'da Environment Variables)
uvicorn main:app --host 0.0.0.0 --port 8000
```

Render: Dashboard → Environment → `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `PULSEDIVE_API_KEY`, `IMAP_SERVER`, `IMAP_USER`, `IMAP_PASS` ekle. Kodda hardcoded key yoktur.

## Endpoint'ler
| Method | Path | Açıklama |
|---|---|---|
| `GET` | `/` | `index.html` |
| `POST` | `/analyze/url` | `{url}` → `{verdict, virustotal, urlhaus, abuseipdb, pulsedive}` |
| `POST` | `/analyze/file` | multipart `file` → `{file_hash, stats, action}` |
| `POST` | `/analyze/imap` | UNSEEN tara → `{results[{subject, from, urls_found, attachments}]}` |

## Test
```bash
pytest -q
```

## Limitler
- Dosya/attachment: 50MB, mail başına 10 URL / 5 ek, IMAP timeout 40sn.
- VT kota (429) / geçersiz key (401) → `503` ile açık mesaj.
