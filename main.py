from fastapi import FastAPI, HTTPException, Depends
from routers import users

app = FastAPI()
# Endpoint for user registration
app.include_router(users.router)

