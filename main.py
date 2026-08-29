from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import os

app = FastAPI(title="Phishing Analyzer Hub")

VT_API_KEY = os.environ.get("VT_API_KEY", "bf00aab82a6caad5ca0d913ad3567663d8d957d1f4e9fb8e76601b59cfff843e")

class AnalyzeRequest(BaseModel):
    url: str

class HashAnalyzeRequest(BaseModel):
    file_hash: str

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
    
    try:
        vt_resp = requests.post(vt_endpoint, data={"url": target_url}, headers=vt_headers)
        if vt_resp.status_code != 200:
            raise HTTPException(status_code=500, detail="VirusTotal URL API'sine ulaşılamadı.")
        result = vt_resp.json()
        analysis_id = result['data']['id']
        return {
            "status": "success",
            "message": "URL analize alındı.",
            "url_scanned": target_url,
            "vt_analysis_id": analysis_id,
            "action": "Karantina kuralları işletiliyor..." 
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/hash")
def analyze_file_hash(request: HashAnalyzeRequest):
    """
    Gelen dosya hash değerini (MD5/SHA256) VirusTotal üzerinden sorgular.
    """
    file_hash = request.file_hash.strip()
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
                "message": "Hash analizi tamamlandı.",
                "file_hash": file_hash,
                "stats": stats,
                "action": f"Zararlı Skoru: Zararlı={stats.get('malicious', 0)}, Temel={stats.get('harmless', 0)}"
            }
        elif vt_resp.status_code == 404:
            return {
                "status": "success",
                "message": "Bu hash veritabanında bulunamadı (Temiz veya bilinmiyor).",
                "file_hash": file_hash,
                "action": "Tehdit algılanmadı."
            }
        else:
            raise HTTPException(status_code=500, detail=f"VirusTotal API Hatası: {vt_resp.status_code}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))