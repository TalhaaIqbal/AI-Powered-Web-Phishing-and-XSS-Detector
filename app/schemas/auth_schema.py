from pydantic import BaseModel, EmailStr, field_validator
import re

class authLogin(BaseModel):
    email: EmailStr
    password: str

class authRegister(BaseModel):
    email: EmailStr
    password: str
    password_confirm: str
    first_name: str
    last_name: str
    phone: str

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

    @field_validator('first_name', 'last_name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or len(v.strip()) < 2:
            raise ValueError('Name must be at least 2 characters long')
        if not re.match(r'^[a-zA-Z\s-]+$', v):
            raise ValueError('Name can only contain letters, spaces, and hyphens')
        return v.strip()

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v: str) -> str:
        if not re.match(r'^\+?[\d\s-()]+$', v):
            raise ValueError('Invalid phone number format')
        digits = re.sub(r'[^\d]', '', v)
        if len(digits) < 10 or len(digits) > 15:
            raise ValueError('Phone number must be between 10 and 15 digits')
        return v

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
