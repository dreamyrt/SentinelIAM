import datetime
from datetime import timedelta, timezone
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import User, AuditLog

SECRET_KEY = "SUPER_SECURE_IAM_KEY_DO_NOT_EXPOSE_IN_PROD_123!"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 45

security = HTTPBearer()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None

def log_audit_event(db: Session, email: str, action: str, status_str: str, details: str, request: Request = None):
    ip = "0.0.0.0"
    if request:
        ip = request.client.host if request.client else "0.0.0.0"

    timestamp = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    log_entry = AuditLog(
        timestamp=timestamp,
        email=email,
        action=action,
        status=status_str,
        ip_address=ip,
        details=details
    )
    db.add(log_entry)
    db.commit()
    print(f"[{timestamp}] [AUDIT] Email: {email} | Action: {action} | Status: {status_str} | IP: {ip} | Details: {details}")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid token")

    if payload.get("type") == "temp":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Complete 2FA verification process")

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account is disabled or missing")
    return user

class RoleChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        if current_user.role not in self.allowed_roles:
            log_audit_event(
                db=db,
                email=current_user.email,
                action="ACCESS_DENIED_RBAC",
                status_str="DENIED",
                details=f"Unauthorized access attempt to resource requiring: {self.allowed_roles}. User role: {current_user.role}",
                request=request
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden. Access restricted to roles: {', '.join(self.allowed_roles)}"
            )
        return current_user