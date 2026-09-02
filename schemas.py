from pydantic import BaseModel, EmailStr

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str

class VerifyMFASchema(BaseModel):
    temp_token: str
    code: str

class EnableMFASchema(BaseModel):
    code: str

class UpdateRoleSchema(BaseModel):
    role: str