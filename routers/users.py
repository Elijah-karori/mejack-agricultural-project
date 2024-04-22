from fastapi import APIRouter
from fastapi import FastAPI, Form, HTTPException
from pydantic import BaseModel
from typing import Optional
from enum import Enum
from fastapi.responses import HTMLResponse
from services.mailersend import send_email
import bcrypt
import string
import random

router = APIRouter()

# Mock database
users_db = []
def generate_otp(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


# User roles
class UserRole(str, Enum):
    admin = "admin"
    customer = "customer"
    worker = "worker"

# Pydantic model for user registration
class User(BaseModel):
    email: str
    password: str
    role: UserRole
    phone_number: Optional[str] = None
    reset_password_otp: Optional[str] = None  # Field to store reset password OTP


@router.get("/users", tags=["login"])
async def get_users():
  async def login(email: str = Form(...), password: str = Form(...)):
    # Check if user exists
    user = next((u for u in users_db if u['email']  == email), None)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
     # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Check user role
    if user['role'] == UserRole.admin:
        # Generate and send OTP
        otp=generate_otp(8)
        # (Implement OTP generation and sending logic here)
        send_email(user["email"],  "User Login", f"User login successfully. Check your email for OTP: {otp}")
        return {"message": "OTP sent to email/phone",'otp':otp}

    elif user['role'] == UserRole.customer:
        # Give options to log in with password or OTP
        otp=generate_otp(6)
        # (Implement OTP generation and sending logic here)
        send_email(user["email"],  "User Login", f"User login successfully. Check your email for OTP: {otp}")
        return {"message": "Choose login method: Password or OTP",'otp':otp}

    elif user['role'] == UserRole.worker:
        # Login with phone number and OTP
        otp=generate_otp(7)
