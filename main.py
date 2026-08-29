from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
import requests
import os
import hashlib

app = FastAPI(title="Phishing Analyzer Hub")

# Zayıf yapılandırma laboratuvar senaryosu
VT_API_KEY = os.environ.get("VT_API_KEY", "bf00aab82a6caad5ca0d913ad3567663d8d957d1f4e9fb8e76601b59cfff843e")

class AnalyzeRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return FileResponse("index.html")

@app.post("/analyze/url")
def analyze_phishing_url(request: AnalyzeRequest):
    target_url = request.url
    
    vt_endpoint = "https://www.virustotal.com/api/v3/urls"
    vt_headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    vt_result = "Erişim Sağlanamadı"
    try:
        vt_resp = requests.post(vt_endpoint, data={"url": target_url}, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_result = vt_resp.json()['data']['id']
        else:
            vt_result = f"Hata ({vt_resp.status_code})"
    except Exception:
        pass

    urlhaus_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    urlhaus_status = "Bilinmiyor"
    try:
        uh_resp = requests.post(urlhaus_endpoint, data={"url": target_url})
        if uh_resp.status_code == 200:
            uh_data = uh_resp.json()
            if uh_data.get('query_status') == 'ok':
                urlhaus_status = f"ZARARLI TESPİT EDİLDİ! (Durum: {uh_data.get('url_status')})"
            else:
                urlhaus_status = "Temiz (URLhaus veritabanında bulunamadı)"
    except Exception:
        urlhaus_status = "Sorgu Hatası"

    return {
        "status": "success",
        "message": "Çoklu İstihbarat Taraması Tamamlandı.",
        "url_scanned": target_url,
        "vt_analysis_id": vt_result,
        "action": f"[URLhaus] -> {urlhaus_status}" 
    }

@app.post("/analyze/file")
async def analyze_uploaded_file(file: UploadFile = File(...)):
    """
    Zafiyet Koruması: Dosya bütün olarak RAM'e alınmaz.
    64KB'lık parçalar (chunks) halinde stream edilerek bellek taşması (OOM) engellenir.
    """
    sha256_hash = hashlib.sha256()
    
    try:
        while chunk := await file.read(65536):
            sha256_hash.update(chunk)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dosya okuma hatası (I/O): {str(e)}")
    finally:
        await file.close() # Fiziksel/Spooled bellek kalıntılarını temizle

    file_hash = sha256_hash.hexdigest()
    
    vt_endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    vt_headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    try:
        vt_resp = requests.get(vt_endpoint, headers=vt_headers)
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
                "message": "Hash veritabanında bulunamadı (Temiz veya Zero-day).",
                "file_hash": file_hash,
                "action": "VT üzerinde tehdit kaydı algılanmadı."
            }
        else:
            raise HTTPException(status_code=500, detail=f"VirusTotal API Hatası: {vt_resp.status_code}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))