"""
app/schemas/auth.py
"""
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int
    username:     str
    role:         str
