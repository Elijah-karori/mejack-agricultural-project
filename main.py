from fastapi import FastAPI, HTTPException, Depends
from routers import users  # Assuming users.py defines user-related endpoints
from fastapi.middleware.cors import CORSMiddleware  # Import for CORS handling

app = FastAPI()

# CORS configuration (replace with allowed origins for your project)
origins = ["http://localhost:3000"]  # Replace with your frontend origin(s)
app.add_middleware(
    CORSMiddleware, 
  allow_origins=origins,
  allow_credentials=True,
  allow_methods=["*"], 
  allow_headers=["*"]
)

# Include user router (assuming users.py defines user-related endpoints)
app.include_router(users.router)

