from sqlalchemy import Column, Integer, String, Boolean
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(String, default="USER")  # USER, ANALYST, ADMIN
    mfa_secret = Column(String, nullable=True)
    is_mfa_enabled = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, nullable=False)
    email = Column(String, nullable=True)
    action = Column(String, nullable=False)
    status = Column(String, nullable=False)  # SUCCESS, DENIED, FAILED
    ip_address = Column(String, nullable=True)
    details = Column(String, nullable=True)