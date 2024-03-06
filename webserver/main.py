import os
import smtplib
from fastapi import FastAPI, Form, HTTPException
from pydantic import BaseModel
from typing import Optional
from enum import Enum
import bcrypt
import string
import random

# Function to send email using smtplib
def send_email(recipient_email, subject, body):
    sender_email = os.environ.get("sender")
    smtp_email = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    
    print(password)


    message = f"""\
    Subject: {subject}
   
    From: {sender_email}

    {body}"""

    try:
        with smtplib.SMTP("smtp.mailgun.org", 587) as server:
            server.login(smtp_email,password)
            server.sendmail(sender_email, recipient_email, message)
        print("Email sent successfully.")
    except Exception as e:
        print(f"An error occurred while sending email: {e}")

app = FastAPI()

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
        "phone_number": user.phone_number,
        "reset_password_otp": None  # Initialize reset password OTP as None
    })

    # Generate OTP and send it via email
    otp = generate_otp(6)
    print(user.email)
    send_email(user.email, "User Registration", f"User registered successfully. Check your email for OTP: {otp}")
    users_db[-1]['reset_password_otp'] = otp  # Update reset password OTP in the database

    return {"message": "User registered successfully. Check your email for OTP.","data":users_db, "otp":otp}

# Endpoint for initiating password reset
@app.post("/reset-password")
async def reset_password(email: str = Form(...)):
    # Find the user by email
    user = next((u for u in users_db if u['email'] == email), None)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate OTP for resetting password
    reset_password_otp = generate_otp(6)
    user['reset_password_otp'] = reset_password_otp  # Update reset password OTP in the database

    # Send OTP via email for resetting password
    send_email(email, "Password Reset OTP", f"Use this OTP to reset your password: {reset_password_otp}")

    return {"message": "Password reset OTP sent to your email. Use it to reset your password.", "email": email}

# Endpoint for verifying OTP and resetting password
@app.post("/reset-password/verify")
async def verify_reset_password(email: str = Form(...), otp: str = Form(...), new_password: str = Form(...)):
    # Find the user by email
    user = next((u for u in users_db if u['email'] == email), None)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify OTP
    if otp != user['reset_password_otp']:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    # Reset password
    user['password'] = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    user['reset_password_otp'] = None  # Clear reset password OTP from the database

    return {"message": "Password reset successfully."}

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
        # (Implement OTP generation and sending logic here)
        send_email(user["email"],  "User Login", f"User login successfully. Check your email for OTP: {otp}")
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
