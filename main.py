import urllib.request
import os
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, EmailStr
from typing import Optional

app = FastAPI(title="FraudGuard API")

# 1. Fetch blocklist on startup
BLOCKLIST_URL = "https://githubusercontent.com"
try:
    with urllib.request.urlopen(BLOCKLIST_URL) as response:
        DISPOSABLE_DOMAINS = set(response.read().decode('utf-8').splitlines())
except Exception:
    DISPOSABLE_DOMAINS = {"mailinator.com", "trashmail.com", "10minutemail.com"}

class CheckEmailRequest(BaseModel):
    email: EmailStr

@app.post("/v1/check-email")
async def check_email(
    data: CheckEmailRequest, 
    # 2. Automatically look for RapidAPI's official security passport header
    x_rapidapi_proxy_secret: Optional[str] = Header(None)
):
    # 3. IF you want to lock it down so ONLY RapidAPI can talk to it, uncomment lines 27-28
    # if x_rapidapi_proxy_secret != os.environ.get("RAPIDAPI_SECRET"):
    #     raise HTTPException(status_code=403, detail="Direct access forbidden. Use RapidAPI storefront.")

    email_domain = data.email.split("@")[-1].lower()
    is_disposable = email_domain in DISPOSABLE_DOMAINS
    
    return {
        "email": data.email,
        "domain": email_domain,
        "is_disposable": is_disposable,
        "risk_score": 95 if is_disposable else 0,
        "recommendation": "BLOCK" if is_disposable else "ALLOW"
    }
