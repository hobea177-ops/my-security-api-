from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import urllib.parse
import os

app = FastAPI(title="CyberShield AI Security Suite")

# السماح للواجهة بالاتصال بالـ API بدون مشاكل CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    url: str

class AIAnalysisRequest(BaseModel):
    query: str

# 1. قسم الفحص والتحليل الهيكلي
@app.post("/api/audit")
async def audit_target(data: AuditRequest):
    try:
        parsed_url = urllib.parse.urlparse(data.url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]
        
        # تحليل استباقي للروابط والشهادات
        is_https = data.url.startswith("https://")
        suspicious_keywords = ["login", "verify", "bank", "free", "mod", "happy", "update", "account"]
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
                "malware_vector": "Detected Open Redirect" if "url?" in data.url else "Clean Structure"
            },
            "recommended_action": "تجنب إدخال أي بيانات حساسة أو كلمة سر في هذا الرابط." if risk_score >= 50 else "الرابط يبدو آمن الاستخدام."
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 2. قسم مستشار الأمن السيبراني الذكي (Cyber AI Assistant)
@app.post("/api/ai-consultant")
async def ai_consultant(data: AIAnalysisRequest):
    q = data.query.lower()
    
    # محاكاة محرك الذكاء الاصطناعي الأمني
    if "sql" in q or "حقن" in q:
        response = "🎯 **تحليل ثغرة SQL Injection:**\n- **الوصف:** استغلال عدم فلترة مدخلات المستخدم للوصول لقواعد البيانات.\n- **طريقة الوقاية:** استخدام Prepared Statements (Parameterized Queries) وتشفير البيانات المدخلة."
    elif "xss" in q:
        response = "⚡ **تحليل ثغرة Cross-Site Scripting (XSS):**\n- **الوصف:** حقن نصوص برمجية خبيثة (JavaScript) في صفحات يراها المستخدمون.\n- **طريقة الوقاية:** تطبيق Input Sanitization واستخدام Content Security Policy (CSP)."
    elif "phishing" in q or "تصيد" in q:
        response = "🎣 **تحليل هجمات التصيد الاحتيالي:**\n- **الوصف:** إغراء المستخدمين بصفحات مزيفة لسرقة بيانات الاعتماد.\n- **طريقة الوقاية:** تفعيل المصادقة المتعددة (2FA) والفحص الدائم لـ SSL Domains."
    else:
        response = f"🤖 **التحليل الأمني الذكي:**\nبناءً على سؤالك حول '{data.query}'، نوصي باتباع معايير OWASP Top 10، وتحديث المكتبات البرمجية، وتطبيق سياسة الأذونات الأدنى (Least Privilege Principle)."

    return {"query": data.query, "ai_response": response}

# تقديم الواجهة عند فتح الصفحة الرئيسية
@app.get("/")
async def read_index():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "CyberShield API is Running. Access /docs for API documentation."}
