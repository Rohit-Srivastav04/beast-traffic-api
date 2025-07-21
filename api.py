from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
import bcrypt
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://clerkme.site", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "*"],
)

# MongoDB Atlas connection
MONGO_URI = "mongodb+srv://Beast:Funday.run.moon12@cluster0.3pb1brz.mongodb.net/myapp?retryWrites=true&w=majority&appName=Cluster0"
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')  # Test connection
    logger.info("MongoDB connection successful")
except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")
    raise
db = client.myapp
users_collection = db.users

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/login")
async def login(request: LoginRequest):
    logger.debug(f"Login attempt for email: {request.email}")
    user = users_collection.find_one({"email": request.email})
    if not user:
        logger.error(f"User not found: {request.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not bcrypt.checkpw(request.password.encode('utf-8'), user["password"].encode('utf-8')):
        logger.error(f"Invalid password for email: {request.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    logger.info(f"Login successful for email: {request.email}")
    return {"message": "Login successful"}

@app.post("/signup")
async def signup(request: LoginRequest):
    logger.debug(f"Signup attempt for email: {request.email}")
    if users_collection.find_one({"email": request.email}):
        logger.error(f"Email already exists: {request.email}")
        raise HTTPException(status_code=400, detail="Email already exists")
    hashed_password = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({
        "email": request.email,
        "password": hashed_password.decode('utf-8'),
        "created_at": datetime.now()
    })
    logger.info(f"Signup successful for email: {request.email}")
    return {"message": "Signup successful"}

@app.options("/signup")
async def options_signup(request: Request):
    logger.debug(f"OPTIONS request received: {request.headers}")
    return {"message": "OPTIONS request allowed"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
