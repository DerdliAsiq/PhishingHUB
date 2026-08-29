from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
import requests
import os
import hashlib
import socket
from urllib.parse import urlparse

app = FastAPI(title="Phishing Analyzer Hub")

VT_API_KEY = os.environ.get("VT_API_KEY", "bf00aab82a6caad5ca0d913ad3567663d8d957d1f4e9fb8e76601b59cfff843e")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "e78fe34f8f81987ad0fdf42b73a8d51e1ebb00b51236a8f837447c794a6f2f6e0a456b97dc0ce3ef")
PULSEDIVE_API_KEY = os.environ.get("PULSEDIVE_API_KEY", "e78fe34f8f81987ad0fdf42b73a8d51e1ebb00b51236a8f837447c794a6f2f6e0a456b97dc0ce3ef")

class AnalyzeRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return FileResponse("index.html")

@app.post("/analyze/url")
def analyze_phishing_url(request: AnalyzeRequest):
    target_url = request.url
    
    # 1. VirusTotal URL Scan
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

    # 2. URLhaus Scan (Fixed: Added User-Agent header to prevent blocking)
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

    # Extract domain and IP for AbuseIPDB & Pulsedive
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    ip_address = None
    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        pass

    # 3. AbuseIPDB Scan
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

    # 4. Pulsedive Scan
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

    # Made output format much more readable using structured HTML layout
    action_summary = (
        f"<br>• <b>URLhaus:</b> {urlhaus_status}"
        f"<br>• <b>AbuseIPDB ({ip_address or 'IP Yok'}):</b> {abuse_status}"
        f"<br>• <b>Pulsedive ({domain}):</b> {pulsedive_status}"
    )

    return {
        "status": "success",
        "message": "Çoklu İstihbarat Taraması Tamamlandı.",
        "url_scanned": target_url,
        "vt_analysis_id": vt_result,
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