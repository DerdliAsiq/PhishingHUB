# PhishingHUB — Passive Security Workspace

Şüpheli URL, dosya ve IMAP mailbox'ını izole analiz eden FastAPI + tek sayfa web uygulaması. **Blue Team triage** odaklı: kanıt öne çıkar, öncelik sırası belirlenir, IOC dışa aktarılır.

## Özellikler
- **URL Scan:** VirusTotal (submit + poll + fallback lookup), URLhaus, AbuseIPDB, Pulsedive — paralel `httpx`, structured `verdict` (malicious / suspicious / clean / unknown).
- **Toplu URL tarama (`/analyze/urls`):** 1–10 URL, tekrarların çıkartılması, geçersiz girişlerin ayrı listelenmesi, öncelik sırası.
- **Dosya:** İstemci tarafında 2 MiB’lik parçalarla **Web Worker (SHA-256)**, dosya içeriği sunucuya gitmez; yalnız hash ve boyut `/analyze/hash` üzerinden sorgulanır. Eski multipart `/analyze/file` 50 MB limitiyle devam eder.
- **IMAP Inbox:** UNSEEN mailler (max 10), `readonly=True` + `BODY.PEEK[]` (mail okunmuş işaretlenmez), `text/plain` + `text/html` link çıkarımı (max 10/mail), attachment SHA-256 + VT lookup (max 5/mail). `IMAP_SCAN_TOKEN` ile korumalı.
- **Lokal phishing kanıtları:** Marka benzerliği (PayPal, Microsoft, Google, Apple), marka-subdomain, `userinfo@`, punycode, IP-hedef, çok katmanlı subdomain. Tüm bunlar `findings` listesinde, tek başına zararlılık kanıtı değildir.
- **VirusTotal bütçe + cache:** Lokal 4 istek/dakika ve 500 istek/gün sınırı; 600 sn / 256 kayıtlı işlemci-bellek cache. Kota doluysa açık `rate_limited` durumu.
- **Güvenlik:** Secret'lar sadece env'den (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `PULSEDIVE_API_KEY`, `IMAP_*`, `OPENROUTER_API_KEY`), frontend `escapeHtml` / DOM API (XSS koruması), `HttpUrl` validasyonu, private-IP skip.
- **AI Asistan (MOD-02):** Son tarama sonucunu OpenRouter free modele sorar, verdict'i Türkçe yorumlar. Context özetlenir (~4KB), ham mail/dosya içeriği gönderilmez, dakikada 10 mesaj/IP limiti, primary + fallback model.
- **Triage Dashboard + IOC:** Metrik kartları, verdict/antivirus grafikleri, öncelikli tablo, phishing bulguları, "sonraki adımlar"; JSON rapor, defang'lı CSV (hxxps / `[.]`), kopyalama ve yazdırma.

## Kurulum
```bash
pip install -r requirements.txt
cp .env.example .env  # gerçek key'leri doldur (Render'da Environment Variables)
uvicorn main:app --host 0.0.0.0 --port 8000
```

Render: Dashboard → Environment → `VT_API_KEY`, `URLHAUS_AUTH_KEY`, `ABUSEIPDB_API_KEY`, `PULSEDIVE_API_KEY`, `IMAP_SERVER`, `IMAP_USER`, `IMAP_PASS`, `OPENROUTER_API_KEY`, `AI_MODEL` ekle. Kodda hardcoded key yoktur. Secret'leri chat'e yapıştırma, `.env.example`'a değer yazma.

## Endpoint'ler
| Method | Path | Açıklama |
|---|---|---|
| `GET` | `/` | `index.html` |
| `POST` | `/analyze/url` | `{url}` → `{verdict, findings, priority, checked_at, virustotal, urlhaus, abuseipdb, pulsedive}` |
| `POST` | `/analyze/urls` | `{urls: [...]}` (1–10) → priorite sıralı sonuçlar + hata listesi |
| `POST` | `/analyze/hash` | `{sha256, file_size?, filename?}` → mevcut VT dosya raporu |
| `POST` | `/analyze/file` | multipart `file` (50 MB) → hash ve VT raporu |
| `POST` | `/analyze/imap` | UNSEEN tara → `{results[{subject, from, urls_found, attachments}]}` |
| `POST` | `/analyze/ai-chat` | `{message, context}` → `{reply, risk, model}` (OpenRouter, key yoksa `503`) |
| `GET` | `/health` | Tüm kaynakların konfigürasyon durumu (değerler asla dönülmez) |

## Test
```bash
pytest -q
```

## Limitler
- Dosya/attachment: 50 MB, mail başına 10 URL / 5 ek, IMAP timeout 40 sn.
- VT kota (429) / geçersiz key (401) → `503` ile açık mesaj. Lokal VT bütçe: 4/dk, 500/gün.
- URL başına maksimum 4 VT çağrısı (submit 1 + poll 2 + fallback lookup 1).
