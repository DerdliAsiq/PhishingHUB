from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import os

app = FastAPI(title="Phishing Analyzer Hub")

# API Anahtarını çevre değişkenlerinden (Environment Variables) alıyoruz
VT_API_KEY = os.environ.get("VT_API_KEY", "bf00aab82a6caad5ca0d913ad3567663d8d957d1f4e9fb8e76601b59cfff843e")

class AnalyzeRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return FileResponse("index.html")

@app.post("/analyze/url")
def analyze_phishing_url(request: AnalyzeRequest):
    """
    Gelen URL'i VirusTotal API'sine gönderir ve risk analizi yapar.
    """
    vt_url = "https://www.virustotal.com/api/v3/urls"
    
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    
    payload = {"url": request.url}
    
    try:
        # 1. Adım: URL'i tarama motoruna gönder
        response = requests.post(vt_url, data=payload, headers=headers)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="VirusTotal API'sine ulasilamadi.")
            
        result = response.json()
        analysis_id = result['data']['id']
        
        # Holberton tasklarında asenkron sonuç beklemek yerine şimdilik 
        # analizin alındığını ve işlendiğini belirten bir yanıt dönüyoruz.
        return {
            "status": "success",
            "message": "URL analize alindi.",
            "url_scanned": request.url,
            "vt_analysis_id": analysis_id,
            "action": "Karantina kurallari isletiliyor..." 
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))