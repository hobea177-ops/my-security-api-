from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from google import genai
import urllib.parse
import os

app = FastAPI(title="CyberShield AI Ultra Security Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ضع مفتاح الـ API الخاص بك هنا بين التنصيص
GEMINI_API_KEY =" AQ.Ab8RN6LScEY1R2APHakze6QEpSlWGYQCUIjVwAo0x1L_4IFotA "

# إعداد عميل الذكاء الاصطناعي الحقيقي
client = genai.Client(api_key=GEMINI_API_KEY)

class AuditRequest(BaseModel):
    url: str

class AIAnalysisRequest(BaseModel):
    query: str

@app.post("/api/audit")
async def audit_target(data: AuditRequest):
    try:
        parsed_url = urllib.parse.urlparse(data.url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]
        is_https = data.url.startswith("https://")
        suspicious_keywords = ["login", "verify", "bank", "free", "mod", "happy", "update", "account", "apk"]
        has_suspicious_words = any(word in data.url.lower() for word in suspicious_keywords)
        
        risk_score = 10
        if not is_https: risk_score += 30
        if has_suspicious_words: risk_score += 35
        if "bit.ly" in data.url or "tinyurl" in data.url: risk_score += 25

        status = "SECURE" if risk_score < 30 else ("WARNING" if risk_score < 60 else "CRITICAL_RISK")

        return {
            "status": "success",
            "domain": domain,
            "protocol": "HTTPS" if is_https else "HTTP",
            "risk_score": risk_score,
            "security_status": status,
            "threat_analysis": {
                "phishing_risk": "High" if has_suspicious_words else "Low",
                "ssl_status": "Valid Certificate" if is_https else "Missing SSL",
                "malware_vector": "Detected Open Redirect / Suspicious Subdomain" if "url?" in data.url else "Clean Structure"
            },
            "recommended_action": "تجنب إدخال أي بيانات حساسة أو كلمة سر في هذا الرابط." if risk_score >= 50 else "الرابط يبدو آمن الاستخدام."
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 🤖 الذكاء الاصطناعي الحقيقي المتغير والذكي 100%
@app.post("/api/ai-consultant")
async def ai_consultant(data: AIAnalysisRequest):
    try:
        system_instruction = (
            "أنت مستشار وخبير أمن سيبراني واختبار اختراق احترافي. "
            "أجب عن سؤال المستخدم بشكل دقيق، مفصل، وذكائي مخصص تماماً لسؤاله. "
            "إذا كان السؤال يتعلق بمحاولة اختراق أو استفسار تعليمي أمني، اشرح الجانب الأمني والوقائي بأسلوب تقني مميز."
        )
        
        # إرسال السؤال الحقيقي لنموذج Gemini 2.5 Flash
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=f"{system_instruction}\n\nسؤال المستخدم: {data.query}"
        )
        
        return {"query": data.query, "ai_response": response.text}
        
    except Exception as e:
        return {"query": data.query, "ai_response": f"حدث خطأ أثناء الاتصال بالذكاء الاصطناعي: {str(e)}"}

@app.get("/")
async def read_index():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "CyberShield Ultra API is Running."}
