from fastapi import FastAPI, Form, HTTPException
from pydantic import BaseModel
from typing import Optional
from enum import Enum
import bcrypt
import string
import random
import smtplib

app = FastAPI()

# Mock database
users_db = []
def generate_otp(length):
    charactersting = string.ascii_letters + string.digits
    return ''.join(random.choice(charactersting) for _ in range(length))
def send_email(email, otp):
    # Implement email sending logic here
    print(f"Sending OTP {otp} to {email}")

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

# Endpoint for user registration
@app.post("/register")
async def register(user: User):
    # Check if user already exists
    if any(u['email'] == user.email for u in users_db):
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash the password
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())

    # Store the user in the database
    users_db.append({
        "email": user.email,
        "password": hashed_password,
        "role": user.role,
        "phone_number": user.phone_number
    })

    # Generate OTP and send it via email
    otp = generate_otp(6)
    #send_email(user.email, otp)

    return {"message": "User registered successfully. Check your email for OTP.","data":users_db, "otp":otp}

# Login endpoint
@app.post("/login")
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
        return {"message": "OTP sent to email/phone",'otp':otp}
    
    elif user['role'] == UserRole.customer:
        # Give options to log in with password or OTP
        otp=generate_otp(6)
        # (Implement OTP generation and sending logic here)
        return {"message": "Choose login method: Password or OTP",'otp':otp}
    
    elif user['role'] == UserRole.worker:
        # Login with phone number and OTP
        otp=generate_otp(7)
        # (Implement OTP generation and sending logic here)
        return {"message": "Login with phone number and OTP",'otp':otp}

# Endpoint for verifying OTP
@app.post("/verify-otp")
async def verify_otp(email: str = Form(...), otp: str = Form(...)):
    # Find the user by email
    user = next((u for u in users_db if u['email'] == email), None)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify OTP
    if otp != user.otp:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    # OTP verification successful, proceed with further actions