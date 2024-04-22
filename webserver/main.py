from fastapi import FastAPI, HTTPException, Depends
from routers import users

app = FastAPI()

app.include_router(users.router)
# Endpoint for user registration
