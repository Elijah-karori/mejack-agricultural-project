# Import necessary modules and classes
from typing import Annotated, Union
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from supabase import create_client, Client
from passlib.context import CryptContext

# Create a FastAPI app instance
app = FastAPI()

# Define constants for JWT
SECRET_KEY = ""  # Add your actual secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Define Supabase connection details
url: str = ""
print(url)  # Consider removing these print statements
key: str = ""
print(key)
supabase: Client = create_client(url, key)

# Define Pydantic models for tokens and user data
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None

class UserInDB(User):
    hashed_password: str

# Create a CryptContext instance for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Define OAuth2 password bearer scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Function to get user from database
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

# Endpoint to get access token
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user_supabase(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Sample protected endpoint
@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}

# Root endpoint
@app.get("/")
async def root():
    return {"users": "data"}

# Endpoint to get tables from Supabase
@app.get("/tables")
async def getTables():
    response = supabase.table('users').select("*").execute()
    print(response)  # Consider removing this print statement
    return response

# Endpoint to create a user in Supabase
@app.post("/createUser")
async def addUser(user_data: dict):
    try:
        response = supabase.table('users').insert([user_data]).execute()
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint to log in a user
@app.post("/login")
async def logUser(credentials: dict):
    try:
        # Extract username and password from credentials
        username = credentials.get("username")
        password = credentials.get("password")

        if not username or not password:
            raise HTTPException(status_code=400, detail="Invalid credentials")

        # Query Supabase for user with matching username
        response = supabase.table('users').select("*").eq('name', username).execute()

        if response["status"] == 200 and response["count"] == 1:
            # Check if the retrieved user has the correct password
            user = response["data"][0]
            if user.get("password") == password:  # This assumes a 'password' field in your user data
                return {"message": "Login successful"}
        
        # If credentials are not valid, raise HTTPException
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
