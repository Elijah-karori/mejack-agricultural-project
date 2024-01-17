from typing import Annotated, Union
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from supabase import create_client, Client
from passlib.context import CryptContext
app = FastAPI()

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

url: str = ""
print(url)
key: str = ""
print(key)
supabase: Client = create_client(url, key)
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str , None] = None


class User(BaseModel):
    username: str
    email:Union [str , None] = None
    full_name: Union[str , None] = None
    disabled:Union [bool , None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
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


@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}


@app.get("/")
async def root():   
    return {"users": "data"}
   

@app.get("/tables")
async def getTables():
          #  supabase: Client = create_client(url, key)
            response = supabase.table('users').select("*").execute()
            print(response)
            return response

@app.post("/createUser")
async def addUser(user_data: dict):
    try:
        response = supabase.table('users').insert([user_data]).execute()
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login")
async def logUser(credentials: dict):
    try:
        # Assuming 'username' and 'password' are keys in the 'credentials' dictionary
        username = credentials.get("username")
        password = credentials.get("password")

        if not username or not password:
            raise HTTPException(status_code=400, detail="Invalid credentials")

        response = supabase.table('users').select("*").eq('name', username).execute()

        if response["status"] == 200 and response["count"] == 1:
            # Check if the retrieved user has the correct password
            user = response["data"][0]
            if user.get("password") == password:
                return {"message": "Login successful"}
        
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
