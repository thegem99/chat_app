# app.py
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.hash import bcrypt
import jwt, os, random
from datetime import datetime, timedelta
from bson import ObjectId
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")

# MongoDB setup
client = AsyncIOMotorClient(MONGO_URI)
db = client["chat_app"]

# FastAPI app
app = FastAPI(title="WhatsApp-like Backend API")

# -------------------
# Pydantic Models
# -------------------
class SignupModel(BaseModel):
    username: str
    email: str
    password: str

class LoginModel(BaseModel):
    email: str
    password: str

class MessageModel(BaseModel):
    receiver_id: str
    message: str

# -------------------
# Auth Functions
# -------------------
async def signup_user(username, email, password):
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    hashed = bcrypt.hash(password)
    result = await db.users.insert_one({
        "username": username,
        "email": email,
        "password": hashed,
        "contacts": [],
        "requests_sent": [],
        "requests_received": []
    })
    return str(result.inserted_id)

async def login_user(email, password):
    user = await db.users.find_one({"email": email})
    if not user or not bcrypt.verify(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    payload = {
        "user_id": str(user["_id"]),
        "exp": datetime.utcnow() + timedelta(days=1)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token

def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# -------------------
# User Routes
# -------------------
@app.post("/users/signup")
async def signup(data: SignupModel):
    user_id = await signup_user(data.username, data.email, data.password)
    return {"user_id": user_id}

@app.post("/users/login")
async def login(data: LoginModel):
    token = await login_user(data.email, data.password)
    return {"token": token}

@app.get("/users/search")
async def search_user(username: str):
    users = await db.users.find({"username": {"$regex": username, "$options": "i"}}).to_list(20)
    for u in users:
        u["_id"] = str(u["_id"])
        u.pop("password", None)
    return users

@app.get("/users/random")
async def random_user():
    count = await db.users.count_documents({})
    if count == 0:
        return {}
    skip = random.randint(0, max(0, count-1))
    user = await db.users.find().skip(skip).limit(1).to_list(1)
    if user:
        user[0]["_id"] = str(user[0]["_id"])
        user[0].pop("password", None)
        return user[0]
    return {}

@app.post("/users/send_request/{receiver_id}")
async def send_request(receiver_id: str, Authorization: str = Header(...)):
    sender_id = verify_token(Authorization.split(" ")[1])
    receiver = await db.users.find_one({"_id": ObjectId(receiver_id)})
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")
    await db.users.update_one({"_id": ObjectId(sender_id)}, {"$addToSet": {"requests_sent": ObjectId(receiver_id)}})
    await db.users.update_one({"_id": ObjectId(receiver_id)}, {"$addToSet": {"requests_received": ObjectId(sender_id)}})
    return {"message": "Request sent"}

@app.post("/users/accept_request/{sender_id}")
async def accept_request(sender_id: str, Authorization: str = Header(...)):
    receiver_id = verify_token(Authorization.split(" ")[1])
    await db.users.update_one(
        {"_id": ObjectId(receiver_id)},
        {"$addToSet": {"contacts": ObjectId(sender_id)}, "$pull": {"requests_received": ObjectId(sender_id)}}
    )
    await db.users.update_one(
        {"_id": ObjectId(sender_id)},
        {"$addToSet": {"contacts": ObjectId(receiver_id)}, "$pull": {"requests_sent": ObjectId(receiver_id)}}
    )
    return {"message": "Request accepted"}

@app.post("/users/remove_contact/{contact_id}")
async def remove_contact(contact_id: str, Authorization: str = Header(...)):
    user_id = verify_token(Authorization.split(" ")[1])
    await db.users.update_one({"_id": ObjectId(user_id)}, {"$pull": {"contacts": ObjectId(contact_id)}})
    await db.users.update_one({"_id": ObjectId(contact_id)}, {"$pull": {"contacts": ObjectId(user_id)}})
    return {"message": "Contact removed"}

# -------------------
# Chat Routes
# -------------------
@app.post("/chat/send")
async def send_message(data: MessageModel, Authorization: str = Header(...)):
    sender_id = verify_token(Authorization.split(" ")[1])
    chat_id = "-".join(sorted([sender_id, data.receiver_id]))
    message_doc = {
        "chat_id": chat_id,
        "sender_id": ObjectId(sender_id),
        "receiver_id": ObjectId(data.receiver_id),
        "message": data.message,
        "timestamp": datetime.utcnow()
    }
    await db.messages.insert_one(message_doc)
    return {"message": "Message sent"}

@app.get("/chat/history/{user_id}")
async def chat_history(user_id: str, Authorization: str = Header(...)):
    me = verify_token(Authorization.split(" ")[1])
    chat_id = "-".join(sorted([me, user_id]))
    msgs = await db.messages.find({"chat_id": chat_id}).to_list(100)
    for m in msgs:
        m["_id"] = str(m["_id"])
        m["sender_id"] = str(m["sender_id"])
        m["receiver_id"] = str(m["receiver_id"])
    return msgs
