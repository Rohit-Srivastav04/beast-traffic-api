from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
import bcrypt
import jwt
from datetime import datetime, timedelta
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://clerkme.site", "https://www.clerkme.site", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "*"],
)

# MongoDB Atlas connection
MONGO_URI = "mongodb+srv://Beast:Funday.run.moon12@cluster0.3pb1brz.mongodb.net/myapp?retryWrites=true&w=majority&appName=Cluster0"
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    logger.info("MongoDB connection successful")
except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")
    raise
db = client.myapp
users_collection = db.users
sessions_collection = db.sessions  # For session management

# JWT settings
SECRET_KEY = "your-secret-key-12345"  # Change this to a strong secret in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 7 * 24 * 60  # 7 days

class UserRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenRequest(BaseModel):
    token: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        session = sessions_collection.find_one({"token": token})
        if not session or session["expiresAt"] < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = users_collection.find_one({"username": username})
        return {"username": username, "isAdmin": user["isAdmin"]}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/signup")
async def signup(request: UserRequest):
    logger.debug(f"Signup attempt for username: {request.username}, email: {request.email}")
    if users_collection.find_one({"$or": [{"email": request.email}, {"username": request.username}]}):
        logger.error(f"User already exists: {request.username}/{request.email}")
        raise HTTPException(status_code=400, detail="Username or email already exists")
    hashed_password = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({
        "username": request.username,
        "email": request.email,
        "password": hashed_password.decode('utf-8'),
        "isAdmin": request.username == "admin",  # Make username "admin" an admin
        "created_at": datetime.now()
    })
    logger.info(f"Signup successful for username: {request.username}")
    return {"message": "Signup successful"}

@app.post("/login")
async def login(request: LoginRequest):
    logger.debug(f"Login attempt for username: {request.username}")
    user = users_collection.find_one({"username": request.username})
    if not user:
        logger.error(f"User not found: {request.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not bcrypt.checkpw(request.password.encode('utf-8'), user["password"].encode('utf-8')):
        logger.error(f"Invalid password for username: {request.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token({"sub": user["username"]})
    expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    sessions_collection.insert_one({
        "username": user["username"],
        "token": token,
        "createdAt": datetime.now(),
        "expiresAt": expires_at
    })
    logger.info(f"Login successful for username: {request.username}")
    return {"token": token, "username": user["username"], "isAdmin": user["isAdmin"]}

@app.post("/validate-token")
async def validate_token(request: TokenRequest):
    return verify_token(request.token)

@app.post("/logout")
async def logout(request: TokenRequest):
    result = sessions_collection.delete_one({"token": request.token})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"message": "Logout successful"}

@app.get("/admin/users")
async def get_users(token: str = Depends(verify_token)):
    if not token["isAdmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    users = list(users_collection.find({}, {"_id": 0, "username": 1, "email": 1}))
    return users

@app.delete("/admin/users/{username}")
async def delete_user(username: str, token: str = Depends(verify_token)):
    if not token["isAdmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    result = users_collection.delete_one({"username": username})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    sessions_collection.delete_many({"username": username})
    return {"message": "User deleted successfully"}

@app.options("/signup")
async def options_signup(request: Request):
    logger.debug(f"OPTIONS request received: {request.headers}")
    return {"message": "OPTIONS request allowed"}

@app.options("/login")
async def options_login(request: Request):
    logger.debug(f"OPTIONS request received: {request.headers}")
    return {"message": "OPTIONS request allowed"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
