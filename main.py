import urllib.request
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

app = FastAPI(
    title="FraudGuard API", 
    description="Instantly detect disposable email addresses."
)

# 1. Fetch an updated open-source blocklist on startup
BLOCKLIST_URL = "https://githubusercontent.com"
try:
    with urllib.request.urlopen(BLOCKLIST_URL) as response:
        # Decode text and convert into a fast-lookup Python Set
        DISPOSABLE_DOMAINS = set(response.read().decode('utf-8').splitlines())
except Exception:
    # Fallback default list if GitHub is temporarily down
    DISPOSABLE_DOMAINS = {"mailinator.com", "trashmail.com", "10minutemail.com"}

# 2. Define the exact input format your users must send
class CheckEmailRequest(BaseModel):
    email: EmailStr

@app.post("/v1/check-email")
async def check_email(data: CheckEmailRequest):
    # 3. Extract the domain name from the user's email input
    email_domain = data.email.split("@")[-1].lower()
    
    # 4. Perform high-speed lookup
    is_disposable = email_domain in DISPOSABLE_DOMAINS
    
    # 5. Return clean JSON to your customer
    return {
        "email": data.email,
        "domain": email_domain,
        "is_disposable": is_disposable,
        "risk_score": 95 if is_disposable else 0,
        "recommendation": "BLOCK" if is_disposable else "ALLOW"
    }
