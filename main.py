from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
import requests
import os
import hashlib
import socket
from urllib.parse import urlparse
import imaplib
import email
from email.header import decode_header
import re

app = FastAPI(title="Phishing Analyzer Hub")

VT_API_KEY = os.environ.get("VT_API_KEY", "bf00aab82a6caad5ca0d913ad3567663d8d957d1f4e9fb8e76601b59cfff843e")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "e78fe34f8f81987ad0fdf42b73a8d51e1ebb00b51236a8f837447c794a6f2f6e0a456b97dc0ce3ef")
PULSEDIVE_API_KEY = os.environ.get("PULSEDIVE_API_KEY", "e78fe34f8f81987ad0fdf42b73a8d51e1ebb00b51236a8f837447c794a6f2f6e0a456b97dc0ce3ef")

IMAP_SERVER = os.environ.get("IMAP_SERVER", "imap.gmail.com")
IMAP_USER = os.environ.get("IMAP_USER", "")
IMAP_PASS = os.environ.get("IMAP_PASS", "")

class AnalyzeRequest(BaseModel):
    url: str

def check_url_intelligence(target_url: str):
    vt_endpoint = "https://www.virustotal.com/api/v3/urls"
    vt_headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    vt_result = "Erişim Sağlanamadı"
    try:
        vt_resp = requests.post(vt_endpoint, data={"url": target_url}, headers=vt_headers, timeout=5)
        if vt_resp.status_code == 200:
            vt_result = vt_resp.json()['data']['id']
        else:
            vt_result = f"Hata ({vt_resp.status_code})"
    except Exception:
        pass

    urlhaus_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    urlhaus_status = "Temiz"
    try:
        uh_headers = {"User-Agent": "PhishGuard-SecurityHub/1.0"}
        uh_resp = requests.post(urlhaus_endpoint, data={"url": target_url}, headers=uh_headers, timeout=5)
        if uh_resp.status_code == 200:
            uh_data = uh_resp.json()
            if uh_data.get('query_status') == 'ok':
                urlhaus_status = f"ZARARLI ({uh_data.get('url_status')})"
            else:
                urlhaus_status = "Temiz (Tehdit Yok)"
    except Exception:
        urlhaus_status = "Temiz"

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    ip_address = None
    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        pass

    abuse_status = "IP Çözümlenemedi"
    if ip_address:
        try:
            abuse_endpoint = "https://api.abuseipdb.com/api/v2/check"
            abuse_headers = {
                "Accept": "application/json",
                "Key": ABUSEIPDB_API_KEY
            }
            abuse_params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
            abuse_resp = requests.get(abuse_endpoint, headers=abuse_headers, params=abuse_params, timeout=5)
            if abuse_resp.status_code == 200:
                abuse_data = abuse_resp.json().get("data", {})
                score = abuse_data.get("abuseConfidenceScore", 0)
                abuse_status = f"Güvenilmezlik Skoru: %{score}"
            else:
                abuse_status = "API Yanıt Vermedi"
        except Exception:
            abuse_status = "Sorgu Hatası"

    pulsedive_status = "Bilinmiyor"
    try:
        pulsedive_endpoint = "https://pulsedive.com/api/indicator.php"
        pulsedive_params = {"indicator": domain, "key": PULSEDIVE_API_KEY}
        pd_resp = requests.get(pulsedive_endpoint, params=pulsedive_params, timeout=5)
        if pd_resp.status_code == 200:
            pd_data = pd_resp.json()
            risk = pd_data.get("risk", "unknown")
            pulsedive_status = f"Risk Seviyesi: {risk.upper()}"
        else:
            pulsedive_status = "Veri Bulunamadı"
    except Exception:
        pulsedive_status = "Sorgu Hatası"

    return {
        "url": target_url,
        "vt_analysis_id": vt_result,
        "urlhaus": urlhaus_status,
        "ip": ip_address or "IP Yok",
        "abuseipdb": abuse_status,
        "pulsedive": pulsedive_status
    }

@app.get("/")
def read_root():
    return FileResponse("index.html")

@app.post("/analyze/url")
def analyze_phishing_url(request: AnalyzeRequest):
    res = check_url_intelligence(request.url)
    action_summary = (
        f"<br>• <b>URLhaus:</b> {res['urlhaus']}"
        f"<br>• <b>AbuseIPDB ({res['ip']}):</b> {res['abuseipdb']}"
        f"<br>• <b>Pulsedive:</b> {res['pulsedive']}"
    )
    return {
        "status": "success",
        "message": "Çoklu İstihbarat Taraması Tamamlandı.",
        "url_scanned": res['url'],
        "vt_analysis_id": res['vt_analysis_id'],
        "action": action_summary 
    }

@app.post("/analyze/file")
async def analyze_uploaded_file(file: UploadFile = File(...)):
    sha256_hash = hashlib.sha256()
    try:
        while chunk := await file.read(65536):
            sha256_hash.update(chunk)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dosya okuma hatası: {str(e)}")
    finally:
        await file.close()

    file_hash = sha256_hash.hexdigest()
    vt_endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    vt_headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    try:
        vt_resp = requests.get(vt_endpoint, headers=vt_headers, timeout=5)
        if vt_resp.status_code == 200:
            data = vt_resp.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                "status": "success",
                "message": "Dosya Hash analizi tamamlandı.",
                "file_hash": file_hash,
                "stats": stats,
                "action": f"Zararlı Skoru: Zararlı={stats.get('malicious', 0)}, Temiz={stats.get('harmless', 0)}, Şüpheli={stats.get('suspicious', 0)}"
            }
        elif vt_resp.status_code == 404:
            return {
                "status": "success",
                "message": "Hash veritabanında bulunamadı.",
                "file_hash": file_hash,
                "action": "VT üzerinde tehdit kaydı algılanmadı."
            }
        else:
            raise HTTPException(status_code=500, detail=f"VirusTotal API Hatası: {vt_resp.status_code}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/imap")
def analyze_imap_inbox():
    if not IMAP_USER or not IMAP_PASS:
        raise HTTPException(status_code=400, detail="IMAP kimlik bilgileri (IMAP_USER / IMAP_PASS) tanımlanmamış.")
    
    analyzed_emails = []
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(IMAP_USER, IMAP_PASS)
        mail.select("INBOX")
        
        status, messages = mail.search(None, "UNSEEN")
        if status != "OK":
            return {"status": "error", "message": "E-posta kutusu taranamadı."}
            
        for num in messages[0].split():
            res, msg_data = mail.fetch(num, "(RFC822)")
            if res != "OK":
                continue
                
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = "Bilinmiyor"
                    if msg["Subject"]:
                        decoded_header = decode_header(msg["Subject"])
                        subject, encoding = decoded_header[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding or "utf-8", errors="ignore")
                    
                    sender = msg.get("From", "Bilinmiyor")
                    
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == "text/plain":
                                payload = part.get_payload(decode=True)
                                if payload:
                                    body += payload.decode("utf-8", errors="ignore")
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body = payload.decode("utf-8", errors="ignore")
                            
                    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
                    url_results = [check_url_intelligence(u) for u in set(urls[:5])]
                    
                    analyzed_emails.append({
                        "subject": subject,
                        "from": sender,
                        "urls_found": url_results
                    })
        
        mail.logout()
        return {
            "status": "success",
            "message": f"{len(analyzed_emails)} okunmamış e-posta analiz edildi.",
            "results": analyzed_emails
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IMAP bağlantı veya analiz hatası: {str(e)}")