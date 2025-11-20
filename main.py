import os
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from hashlib import sha256
from database import db, get_documents
from schemas import B2BUser

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
            
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    
    import os
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    
    return response

# ------------ B2B Login API -------------
class LoginRequest(BaseModel):
    company_code: str
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    status: str
    message: str
    user: Optional[dict] = None


def hash_password(password: str) -> str:
    return sha256(password.encode("utf-8")).hexdigest()

@app.post("/auth/b2b/login", response_model=LoginResponse)
async def b2b_login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Find user by tenant + email
    users = get_documents(
        collection_name="b2buser",
        filter_dict={"company_code": payload.company_code.upper(), "email": payload.email.lower()},
        limit=1,
    )

    if not users:
        return LoginResponse(status="error", message="Invalid credentials")

    user = users[0]

    if user.get("is_active") is False:
        return LoginResponse(status="error", message="Account disabled")

    if user.get("password_hash") != hash_password(payload.password):
        return LoginResponse(status="error", message="Invalid credentials")

    # Remove sensitive fields
    sanitized = {
        "id": str(user.get("_id")),
        "name": user.get("name"),
        "email": user.get("email"),
        "company_code": user.get("company_code"),
        "role": user.get("role", "member"),
    }

    return LoginResponse(status="success", message="Login successful", user=sanitized)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
