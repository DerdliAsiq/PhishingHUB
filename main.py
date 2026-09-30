from contextlib import asynccontextmanager
from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from pydantic import BaseModel, HttpUrl, field_validator
from pathlib import Path
from urllib.parse import urlparse
from email.header import decode_header
from email.message import Message
import asyncio
import base64
import hashlib
import imaplib
import email
import ipaddress
import os
import re
import socket

import httpx

BASE_DIR = Path(__file__).resolve().parent

# --- Secrets: env only, no hardcoded defaults ---
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
PULSEDIVE_API_KEY = os.getenv("PULSEDIVE_API_KEY")

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_USER = os.getenv("IMAP_USER", "")
IMAP_PASS = os.getenv("IMAP_PASS", "")

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_MAILS = 10
MAX_URLS_PER_MAIL = 10
MAX_ATTACHMENTS_PER_MAIL = 5
HTTP_TIMEOUT = 8.0

URL_RE = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.IGNORECASE)
HREF_RE = re.compile(r'href\s*=\s*["\'](https?://[^"\']+|www\.[^"\']+)["\']', re.IGNORECASE)

_http_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client
    _http_client = httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": "PhishingHUB/1.0"})
    try:
        yield
    finally:
        if _http_client is not None:
            await _http_client.aclose()
            _http_client = None


app = FastAPI(title="PhishingHUB", lifespan=lifespan)


def get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        # lifespan çalışmadan gelen çağrılar (örn. TestClient without context) için lazy fallback
        _http_client = httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": "PhishingHUB/1.0"})
    return _http_client


class AnalyzeRequest(BaseModel):
    url: HttpUrl

    @field_validator("url")
    @classmethod
    def check_length(cls, v: HttpUrl) -> HttpUrl:
        s = str(v)
        if len(s) > 2048:
            raise ValueError("URL çok uzun (max 2048).")
        return v


def strip_trailing_punct(u: str) -> str:
    return u.rstrip('.,);]\'"!')


def normalize_url(raw: str) -> str | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    raw = strip_trailing_punct(raw)
    if len(raw) > 2048:
        return None
    if raw.lower().startswith("www."):
        raw = "https://" + raw
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlparse(raw)
        if not p.netloc or "." not in p.netloc:
            return None
        return raw
    except Exception:
        return None


def extract_domain(target_url: str) -> str:
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain.strip().lower()
    except Exception:
        return ""


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except Exception:
        return True


def vt_url_id(target_url: str) -> str:
    return base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")


def compute_overall_verdict(vt: dict, urlhaus: dict, abuse: dict, pulsedive: dict) -> str:
    vt_stats = (vt or {}).get("stats") or {}
    try:
        if int(vt_stats.get("malicious", 0)) > 0:
            return "malicious"
    except Exception:
        pass
    if (urlhaus or {}).get("status") == "malicious":
        return "malicious"
    try:
        if int(vt_stats.get("suspicious", 0)) > 0:
            return "suspicious"
    except Exception:
        pass
    risk = str((pulsedive or {}).get("risk", "")).lower()
    if risk in ("high", "medium"):
        return "suspicious"
    try:
        score = abuse.get("score")
        if score is not None and int(score) >= 50:
            return "suspicious"
    except Exception:
        pass
    if vt.get("status") == "error" and urlhaus.get("status") == "error":
        return "unknown"
    return "clean"


async def fetch_vt_verdict(client: httpx.AsyncClient, target_url: str) -> dict:
    if not VT_API_KEY:
        return {"status": "error", "error": "VT_API_KEY yapılandırılmamış (env).", "stats": {}, "verdict": "unknown", "analysis_id": None}
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    analysis_id = None
    # 1) Submit URL
    try:
        r = await client.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": target_url},
            headers={**headers, "content-type": "application/x-www-form-urlencoded"},
        )
        if r.status_code == 401:
            return {"status": "error", "error": "VirusTotal: geçersiz API anahtarı (401).", "stats": {}, "verdict": "unknown", "analysis_id": None}
        if r.status_code == 429:
            return {"status": "error", "error": "VirusTotal: kota aşıldı (429).", "stats": {}, "verdict": "unknown", "analysis_id": None}
        if r.status_code == 200:
            try:
                analysis_id = r.json()["data"]["id"]
            except Exception:
                analysis_id = None
        else:
            # Submit başarısızsa direkt url lookup fallback'ına git
            analysis_id = None
    except Exception as e:
        return {"status": "error", "error": f"VirusTotal submit hatası: {type(e).__name__}", "stats": {}, "verdict": "unknown", "analysis_id": None}

    # 2) Poll analysis
    if analysis_id:
        for _ in range(7):
            try:
                pr = await client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
                if pr.status_code == 200:
                    data = pr.json().get("data", {}).get("attributes", {})
                    if data.get("status") == "completed":
                        stats = data.get("stats", {}) or {}
                        verdict = "clean"
                        try:
                            if int(stats.get("malicious", 0)) > 0:
                                verdict = "malicious"
                            elif int(stats.get("suspicious", 0)) > 0:
                                verdict = "suspicious"
                        except Exception:
                            pass
                        return {"status": "completed", "stats": stats, "verdict": verdict, "analysis_id": analysis_id}
                elif pr.status_code in (401, 429):
                    break
            except Exception:
                pass
            await asyncio.sleep(2)

    # 3) Fallback: url lookup
    try:
        uid = vt_url_id(target_url)
        lr = await client.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers=headers)
        if lr.status_code == 200:
            attrs = lr.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}
            verdict = "clean"
            try:
                if int(stats.get("malicious", 0)) > 0:
                    verdict = "malicious"
                elif int(stats.get("suspicious", 0)) > 0:
                    verdict = "suspicious"
            except Exception:
                pass
            return {"status": "completed", "stats": stats, "verdict": verdict, "analysis_id": analysis_id}
        if lr.status_code == 404:
            return {"status": "completed", "stats": {}, "verdict": "unknown", "analysis_id": analysis_id, "note": "VT'de kayıt yok."}
    except Exception:
        pass
    return {"status": "timeout", "error": "VT analizi tamamlanamadı (timeout).", "stats": {}, "verdict": "unknown", "analysis_id": analysis_id}


async def fetch_urlhaus(client: httpx.AsyncClient, target_url: str) -> dict:
    try:
        r = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": target_url})
        if r.status_code != 200:
            return {"status": "error", "detail": f"HTTP {r.status_code}"}
        data = r.json()
        if data.get("query_status") == "ok":
            return {"status": "malicious", "detail": str(data.get("url_status", "listed"))}
        return {"status": "clean", "detail": "Tehdit kaydı yok"}
    except Exception as e:
        return {"status": "error", "detail": f"{type(e).__name__}"}


async def resolve_ip(domain: str) -> str | None:
    if not domain:
        return None
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, domain, None)
        if infos:
            return infos[0][4][0]
        return None
    except Exception:
        return None


async def fetch_abuseipdb(client: httpx.AsyncClient, ip_address: str | None) -> dict:
    if not ip_address:
        return {"ip": None, "score": None, "status": "IP çözümlenemedi"}
    if is_private_ip(ip_address):
        return {"ip": ip_address, "score": None, "status": "private IP - atlandı"}
    if not ABUSEIPDB_API_KEY:
        return {"ip": ip_address, "score": None, "status": "ABUSEIPDB_API_KEY yapılandırılmamış (env)"}
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
            params={"ipAddress": ip_address, "maxAgeInDays": "90"},
        )
        if r.status_code != 200:
            return {"ip": ip_address, "score": None, "status": f"API yanıt vermedi ({r.status_code})"}
        score = r.json().get("data", {}).get("abuseConfidenceScore", 0)
        try:
            score = int(score)
        except Exception:
            score = 0
        return {"ip": ip_address, "score": score, "status": f"Güvenilmezlik skoru: %{score}"}
    except Exception:
        return {"ip": ip_address, "score": None, "status": "Sorgu hatası"}


async def fetch_pulsedive(client: httpx.AsyncClient, domain: str) -> dict:
    if not domain:
        return {"risk": "unknown", "status": "domain yok"}
    if not PULSEDIVE_API_KEY:
        return {"risk": "unknown", "status": "PULSEDIVE_API_KEY yapılandırılmamış (env)"}
    try:
        r = await client.get("https://pulsedive.com/api/indicator.php", params={"indicator": domain, "key": PULSEDIVE_API_KEY})
        if r.status_code != 200:
            return {"risk": "unknown", "status": "Veri bulunamadı"}
        risk = str(r.json().get("risk", "unknown")).lower()
        return {"risk": risk, "status": f"Risk seviyesi: {risk.upper()}"}
    except Exception:
        return {"risk": "unknown", "status": "Sorgu hatası"}


async def check_url_intelligence(target_url: str) -> dict:
    client = get_client()
    domain = extract_domain(target_url)
    vt_task = fetch_vt_verdict(client, target_url)
    urlhaus_task = fetch_urlhaus(client, target_url)
    pulsedive_task = fetch_pulsedive(client, domain)
    dns_task = resolve_ip(domain)
    vt_res, urlhaus_res, pulsedive_res, ip_addr = await asyncio.gather(vt_task, urlhaus_task, pulsedive_task, dns_task)
    abuse_res = await fetch_abuseipdb(client, ip_addr)
    verdict = compute_overall_verdict(vt_res, urlhaus_res, abuse_res, pulsedive_res)
    return {
        "url": target_url,
        "verdict": verdict,
        "virustotal": vt_res,
        "urlhaus": urlhaus_res,
        "ip": ip_addr or "IP Yok",
        "abuseipdb": abuse_res,
        "pulsedive": pulsedive_res,
    }


async def vt_file_lookup(client: httpx.AsyncClient, file_hash: str) -> dict:
    if not VT_API_KEY:
        raise HTTPException(status_code=503, detail="VT_API_KEY yapılandırılmamış (env).")
    r = await client.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"accept": "application/json", "x-apikey": VT_API_KEY},
    )
    return r


# ---------- IMAP helpers (blocking part runs in thread) ----------

def decode_mime_header(value: str | None) -> str:
    if not value:
        return "Bilinmiyor"
    try:
        parts = decode_header(value)
        out = ""
        for content, enc in parts:
            if isinstance(content, bytes):
                out += content.decode(enc or "utf-8", errors="ignore")
            else:
                out += str(content)
        return out or "Bilinmiyor"
    except Exception:
        return "Bilinmiyor"


def extract_urls_from_blob(text: str, html: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    candidates: list[str] = []
    if html:
        try:
            candidates.extend(HREF_RE.findall(html))
        except Exception:
            pass
    if text:
        candidates.extend(URL_RE.findall(text))
    if html and not text:
        # HTML içindeki çıplak URL'leri de yakala
        try:
            candidates.extend(URL_RE.findall(html))
        except Exception:
            pass
    for raw in candidates:
        norm = normalize_url(raw)
        if norm and norm not in seen:
            seen.add(norm)
            found.append(norm)
        if len(found) >= MAX_URLS_PER_MAIL:
            break
    return found


def parse_email_bytes(raw_bytes: bytes) -> dict:
    msg = email.message_from_bytes(raw_bytes)
    subject = decode_mime_header(msg.get("Subject"))
    sender = decode_mime_header(msg.get("From"))
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []

    def handle_part(part: Message):
        ctype = part.get_content_type()
        disp = str(part.get("Content-Disposition") or "")
        filename = part.get_filename()
        is_attachment = "attachment" in disp.lower() or (filename and ctype != "text/plain" and ctype != "text/html")
        payload = None
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if is_attachment:
            if len(attachments) >= MAX_ATTACHMENTS_PER_MAIL:
                return
            try:
                fname = decode_mime_header(filename) if filename else "isimsiz"
            except Exception:
                fname = filename or "isimsiz"
            if not payload:
                attachments.append({"filename": fname, "size": 0, "sha256": None, "note": "içerik okunamadı"})
                return
            if len(payload) > MAX_FILE_SIZE:
                attachments.append({"filename": fname, "size": len(payload), "sha256": None, "note": "limit aşıldı (50MB)"})
                return
            h = hashlib.sha256(payload).hexdigest()
            attachments.append({"filename": fname, "size": len(payload), "sha256": h})
            return
        if ctype == "text/plain":
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    text_parts.append(payload.decode(charset, errors="ignore"))
                except Exception:
                    text_parts.append(payload.decode("utf-8", errors="ignore"))
        elif ctype == "text/html":
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    html_parts.append(payload.decode(charset, errors="ignore"))
                except Exception:
                    html_parts.append(payload.decode("utf-8", errors="ignore"))

    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                handle_part(part)
        else:
            handle_part(msg)
    except Exception:
        pass

    body_text = "\n".join(text_parts)
    body_html = "\n".join(html_parts)
    urls = extract_urls_from_blob(body_text, body_html)
    return {"subject": subject, "from": sender, "urls": urls, "attachments": attachments}


def fetch_imap_mails_sync() -> list[dict]:
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    try:
        mail.login(IMAP_USER, IMAP_PASS)
        mail.select("INBOX")
        status, messages = mail.search(None, "UNSEEN")
        if status != "OK":
            raise RuntimeError("E-posta kutusu taranamadı.")
        nums = (messages[0].split() if messages and messages[0] else [])[:MAX_MAILS]
        out: list[dict] = []
        for num in nums:
            res, msg_data = mail.fetch(num, "(RFC822)")
            if res != "OK":
                continue
            for response_part in msg_data:
                if isinstance(response_part, tuple) and len(response_part) >= 2 and isinstance(response_part[1], (bytes, bytearray)):
                    parsed = parse_email_bytes(bytes(response_part[1]))
                    out.append(parsed)
        return out
    finally:
        try:
            mail.logout()
        except Exception:
            pass


async def enrich_attachment_vt(client: httpx.AsyncClient, att: dict) -> dict:
    h = att.get("sha256")
    if not h:
        return {**att, "vt": {"status": "skipped", "detail": att.get("note", "hash yok")}}
    if not VT_API_KEY:
        return {**att, "vt": {"status": "error", "detail": "VT_API_KEY yok"}}
    try:
        r = await client.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={"accept": "application/json", "x-apikey": VT_API_KEY})
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {**att, "vt": {"status": "completed", "stats": stats}}
        if r.status_code == 404:
            return {**att, "vt": {"status": "clean", "detail": "VT'de kayıt yok"}}
        return {**att, "vt": {"status": "error", "detail": f"HTTP {r.status_code}"}}
    except Exception as e:
        return {**att, "vt": {"status": "error", "detail": type(e).__name__}}


@app.get("/")
def read_root():
    index_path = BASE_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=500, detail="index.html bulunamadı.")
    return FileResponse(str(index_path))


@app.post("/analyze/url")
async def analyze_phishing_url(request: AnalyzeRequest):
    res = await check_url_intelligence(str(request.url))
    return {
        "status": "success",
        "message": "Çoklu istihbarat taraması tamamlandı.",
        "url_scanned": res["url"],
        "verdict": res["verdict"],
        "virustotal": res["virustotal"],
        "urlhaus": res["urlhaus"],
        "ip": res["ip"],
        "abuseipdb": res["abuseipdb"],
        "pulsedive": res["pulsedive"],
        # legacy uyumluluk
        "vt_analysis_id": (res["virustotal"] or {}).get("analysis_id") or "Yok",
    }


@app.post("/analyze/file")
async def analyze_uploaded_file(request: Request, file: UploadFile = File(...)):
    # Erken Content-Length kontrolü (env'den bağımsız, önce limit)
    try:
        cl = request.headers.get("content-length")
        if cl is not None and int(cl) > MAX_FILE_SIZE + 1024 * 1024:
            raise HTTPException(status_code=413, detail="Dosya çok büyük (limit 50MB).")
    except HTTPException:
        raise
    except Exception:
        pass

    sha256_hash = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = await file.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="Dosya çok büyük (limit 50MB).")
            sha256_hash.update(chunk)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dosya okuma hatası: {str(e)}")
    finally:
        try:
            await file.close()
        except Exception:
            pass

    file_hash = sha256_hash.hexdigest()
    client = get_client()
    try:
        vt_resp = await vt_file_lookup(client, file_hash)
        if vt_resp.status_code == 200:
            stats = vt_resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "message": "Dosya hash analizi tamamlandı.",
                "file_hash": file_hash,
                "file_size": total,
                "stats": stats,
                "action": f"Zararlı={stats.get('malicious', 0)}, Temiz={stats.get('harmless', 0)}, Şüpheli={stats.get('suspicious', 0)}",
            }
        if vt_resp.status_code == 404:
            return {
                "status": "success",
                "message": "Hash veritabanında bulunamadı.",
                "file_hash": file_hash,
                "file_size": total,
                "action": "VT üzerinde tehdit kaydı algılanmadı.",
            }
        if vt_resp.status_code == 401:
            raise HTTPException(status_code=503, detail="VirusTotal: geçersiz API anahtarı.")
        if vt_resp.status_code == 429:
            raise HTTPException(status_code=503, detail="VirusTotal: kota aşıldı, sonra tekrar deneyin.")
        raise HTTPException(status_code=500, detail=f"VirusTotal API hatası: {vt_resp.status_code}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/imap")
async def analyze_imap_inbox():
    if not IMAP_USER or not IMAP_PASS:
        raise HTTPException(status_code=400, detail="IMAP kimlik bilgileri (IMAP_USER / IMAP_PASS) tanımlanmamış.")
    try:
        mails = await asyncio.wait_for(asyncio.to_thread(fetch_imap_mails_sync), timeout=40)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="IMAP zaman aşımı (40sn).")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IMAP bağlantı veya analiz hatası: {str(e)}")

    client = get_client()
    analyzed = []
    for m in mails:
        url_results = []
        # URL'leri paralel tara
        if m.get("urls"):
            url_results = list(await asyncio.gather(*[check_url_intelligence(u) for u in m["urls"]]))
        att_results = []
        if m.get("attachments"):
            att_results = list(await asyncio.gather(*[enrich_attachment_vt(client, a) for a in m["attachments"]]))
        analyzed.append({
            "subject": m.get("subject", "Bilinmiyor"),
            "from": m.get("from", "Bilinmiyor"),
            "urls_found": url_results,
            "attachments": att_results,
        })

    return {
        "status": "success",
        "message": f"{len(analyzed)} okunmamış e-posta analiz edildi.",
        "results": analyzed,
    }
