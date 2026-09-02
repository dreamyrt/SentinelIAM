import os
import base64
from io import BytesIO
from datetime import timedelta
import pyotp
import qrcode
import uvicorn
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.orm import Session

from database import engine, Base, SessionLocal, get_db
from models import User, AuditLog
from schemas import UserLoginSchema, VerifyMFASchema, EnableMFASchema, UpdateRoleSchema
from security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    log_audit_event,
    get_current_user,
    RoleChecker
)

def seed_database(db: Session):
    if db.query(User).count() == 0:
        test_users = [
            {
                "email": "user@company.com",
                "password": "User123!",
                "full_name": "Standard User",
                "role": "USER"
            },
            {
                "email": "analyst@company.com",
                "password": "Analyst123!",
                "full_name": "Security Analyst",
                "role": "ANALYST"
            },
            {
                "email": "admin@company.com",
                "password": "Admin123!",
                "full_name": "System Administrator",
                "role": "ADMIN"
            }
        ]
        for u in test_users:
            new_user = User(
                email=u["email"],
                hashed_password=hash_password(u["password"]),
                full_name=u["full_name"],
                role=u["role"],
                is_active=True,
                is_mfa_enabled=False
            )
            db.add(new_user)
        db.commit()
        print("[DB] Test accounts successfully seeded.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()
    yield

app = FastAPI(title="SentinelIAM Workspace", lifespan=lifespan)

# МАРШРУТ ДЛЯ ВІДДАЧІ ЛОГОТИПА З КОРЕНЕВОЇ ПАПКИ
@app.get("/logo.png")
def get_logo():
    logo_path = os.path.join(os.path.dirname(__file__), "logo.png")
    if os.path.exists(logo_path):
        return FileResponse(logo_path)
    # Якщо логотип відсутній, бекенд повертає 404 помилку, а фронтенд застосує резервний іконковий варіант
    raise HTTPException(status_code=404, detail="logo.png not found in root directory")

# МАРШРУТИ АУТЕНТИФІКАЦІЇ ТА 2FA

@app.post("/api/auth/login")
def login(schema: UserLoginSchema, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == schema.email).first()
    if not user or not verify_password(schema.password, user.hashed_password):
        log_audit_event(db, schema.email, "LOGIN_ATTEMPT", "FAILED", "Invalid email or password input.", request)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=401, detail="Your account is deactivated")

    if user.is_mfa_enabled:
        temp_token = create_access_token(
            data={"sub": str(user.id), "type": "temp"},
            expires_delta=timedelta(minutes=5)
        )
        log_audit_event(db, user.email, "MFA_CHALLENGE", "SUCCESS", "Primary login successful. Requesting MFA Challenge.", request)
        return {"mfa_required": True, "temp_token": temp_token}

    access_token = create_access_token(data={"sub": str(user.id), "role": user.role})
    log_audit_event(db, user.email, "LOGIN_COMPLETE", "SUCCESS", "User authenticated successfully (MFA disabled).", request)
    return {
        "mfa_required": False,
        "access_token": access_token,
        "role": user.role,
        "full_name": user.full_name,
        "email": user.email
    }

@app.post("/api/auth/verify-mfa")
def verify_mfa_challenge(schema: VerifyMFASchema, request: Request, db: Session = Depends(get_db)):
    payload = decode_access_token(schema.temp_token)
    if not payload or payload.get("type") != "temp":
        raise HTTPException(status_code=401, detail="Invalid or expired MFA session")

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid session credentials")

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(schema.code):
        log_audit_event(db, user.email, "MFA_VERIFY", "FAILED", "Incorrect TOTP code input.", request)
        raise HTTPException(status_code=400, detail="Invalid verification code")

    access_token = create_access_token(data={"sub": str(user.id), "role": user.role})
    log_audit_event(db, user.email, "LOGIN_COMPLETE", "SUCCESS", "User logged in with multi-factor authentication.", request)
    return {
        "access_token": access_token,
        "role": user.role,
        "full_name": user.full_name,
        "email": user.email
    }

@app.post("/api/mfa/setup")
def setup_mfa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA has already been enabled")

    secret = pyotp.random_base32()
    current_user.mfa_secret = secret
    db.commit()

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="SentinelIAM")

    img = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return {
        "secret": secret,
        "qr_code": f"data:image/png;base64,{img_str}"
    }

@app.post("/api/mfa/enable")
def enable_mfa(schema: EnableMFASchema, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA has already been enabled")

    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="Run MFA setup request first")

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(schema.code):
        log_audit_event(db, current_user.email, "MFA_ENABLE_ATTEMPT", "FAILED", "Attempted to enable MFA with invalid code.", request)
        raise HTTPException(status_code=400, detail="Invalid verification code")

    current_user.is_mfa_enabled = True
    db.commit()
    log_audit_event(db, current_user.email, "MFA_ENABLE_COMPLETE", "SUCCESS", "Multi-factor authentication successfully activated.", request)
    return {"message": "MFA has been successfully activated."}

@app.post("/api/mfa/disable")
def disable_mfa(schema: EnableMFASchema, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(schema.code):
        log_audit_event(db, current_user.email, "MFA_DISABLE_ATTEMPT", "FAILED", "Invalid verification code to disable MFA.", request)
        raise HTTPException(status_code=400, detail="Invalid verification code")

    current_user.is_mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()
    log_audit_event(db, current_user.email, "MFA_DISABLE_COMPLETE", "SUCCESS", "Multi-factor authentication deactivated.", request)
    return {"message": "MFA has been successfully deactivated."}

# МАРШРУТИ РОБОЧОГО КАБІНЕТУ ТА АДМІНІСТРУВАННЯ

@app.get("/api/workspace/profile")
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "is_mfa_enabled": current_user.is_mfa_enabled
    }

@app.get("/api/workspace/metrics")
def get_metrics(
        request: Request,
        current_user: User = Depends(RoleChecker(allowed_roles=["ANALYST", "ADMIN"])),
        db: Session = Depends(get_db)
):
    import random
    metrics = {
        "cpu_usage": random.randint(20, 80),
        "memory_usage": random.randint(45, 90),
        "active_sessions": random.randint(10, 120),
        "blocked_attacks": random.randint(250, 1800),
        "system_status": "Secure",
        "logs_summary": [
            {"time": "14:00", "threats": random.randint(0, 5)},
            {"time": "15:00", "threats": random.randint(2, 9)},
            {"time": "16:00", "threats": random.randint(1, 15)},
            {"time": "17:00", "threats": random.randint(3, 8)},
            {"time": "18:00", "threats": random.randint(0, 4)},
            {"time": "19:00", "threats": random.randint(1, 11)}
        ]
    }
    return metrics

@app.get("/api/admin/users")
def get_users(
        request: Request,
        current_user: User = Depends(RoleChecker(allowed_roles=["ADMIN"])),
        db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return [{
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
        "is_mfa_enabled": u.is_mfa_enabled
    } for u in users]

@app.put("/api/admin/users/{user_id}/role")
def change_role(
        user_id: int,
        schema: UpdateRoleSchema,
        request: Request,
        current_user: User = Depends(RoleChecker(allowed_roles=["ADMIN"])),
        db: Session = Depends(get_db)
):
    if schema.role not in ["USER", "ANALYST", "ADMIN"]:
        raise HTTPException(status_code=400, detail="Invalid role type")

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = target_user.role
    target_user.role = schema.role
    db.commit()

    log_audit_event(
        db,
        current_user.email,
        "ROLE_CHANGE",
        "SUCCESS",
        f"Modified user role [{target_user.email}] from '{old_role}' to '{schema.role}'.",
        request
    )
    return {"message": "Role modified successfully"}

@app.get("/api/admin/audit-logs")
def get_audit_logs(
        request: Request,
        current_user: User = Depends(RoleChecker(allowed_roles=["ADMIN"])),
        db: Session = Depends(get_db)
):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
    return [{
        "id": l.id,
        "timestamp": l.timestamp,
        "email": l.email,
        "action": l.action,
        "status": l.status,
        "ip_address": l.ip_address,
        "details": l.details
    } for l in logs]


# ВІДОБРАЖЕННЯ ФРОНТЕНДУ

@app.get("/", response_class=HTMLResponse)
def index():
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Frontend template index.html missing in templates/ folder")


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)