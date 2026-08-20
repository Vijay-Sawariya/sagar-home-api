from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from passlib.context import CryptContext
import jwt
from bson import ObjectId

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI()
api_router = APIRouter(prefix="/api")

# ============= Helper Functions =============
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        user["_id"] = str(user["_id"])
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============= Models =============
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    email: EmailStr
    role: str = "user"  # admin, manager, user, caller

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    full_name: str
    email: str
    role: str
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class BuilderCreate(BaseModel):
    builder_name: str
    company_name: str
    phone: str
    address: Optional[str] = None

class BuilderResponse(BaseModel):
    id: str
    builder_name: str
    company_name: str
    phone: str
    address: Optional[str]
    created_at: datetime

class LeadCreate(BaseModel):
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    lead_type: Optional[str] = "buyer"  # buyer, seller, rent, landlord, tenant
    location: Optional[str] = None
    address: Optional[str] = None
    bhk: Optional[str] = None
    budget_min: Optional[float] = None
    budget_max: Optional[float] = None
    property_type: Optional[str] = None
    lead_status: Optional[str] = "New"
    lead_temperature: Optional[str] = "Hot"  # Hot, Warm, Cold
    notes: Optional[str] = None
    builder_id: Optional[str] = None
    next_followup_date: Optional[datetime] = None

class LeadResponse(BaseModel):
    id: str
    name: str
    email: Optional[str]
    phone: Optional[str]
    lead_type: Optional[str]
    location: Optional[str]
    address: Optional[str]
    bhk: Optional[str]
    budget_min: Optional[float]
    budget_max: Optional[float]
    property_type: Optional[str]
    lead_status: Optional[str]
    lead_temperature: Optional[str]
    notes: Optional[str]
    builder_id: Optional[str]
    next_followup_date: Optional[datetime]
    created_at: datetime
    created_by: Optional[str]

class ReminderCreate(BaseModel):
    lead_id: Optional[str] = None
    title: str
    reminder_date: datetime
    reminder_type: str  # Call, WhatsApp, Email, Meeting, Site Visit
    notes: Optional[str] = None
    send_whatsapp: bool = False
    whatsapp_message: Optional[str] = None

class ReminderResponse(BaseModel):
    id: str
    lead_id: Optional[str]
    title: str
    reminder_date: datetime
    reminder_type: str
    notes: Optional[str]
    status: str
    send_whatsapp: bool
    whatsapp_message: Optional[str]
    created_by: str
    created_at: datetime
    notified: bool

class WhatsAppMessageCreate(BaseModel):
    phone: str
    message: str
    lead_id: Optional[str] = None

class WhatsAppLogResponse(BaseModel):
    id: str
    phone: str
    message: str
    lead_id: Optional[str]
    status: str
    created_at: datetime

class DashboardStats(BaseModel):
    total_leads: int
    hot_leads: int
    warm_leads: int
    cold_leads: int
    total_builders: int
    today_reminders: int
    pending_reminders: int

# ============= Auth Routes =============
@api_router.post("/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    # Check if user exists
    existing = await db.users.find_one({"username": user_data.username})
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    user_dict = user_data.dict()
    user_dict["password"] = get_password_hash(user_data.password)
    user_dict["created_at"] = datetime.utcnow()
    
    result = await db.users.insert_one(user_dict)
    user = await db.users.find_one({"_id": result.inserted_id})
    
    return UserResponse(
        id=str(user["_id"]),
        username=user["username"],
        full_name=user["full_name"],
        email=user["email"],
        role=user["role"],
        created_at=user["created_at"]
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"username": credentials.username})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": str(user["_id"])})
    
    return TokenResponse(
        access_token=access_token,
        user=UserResponse(
            id=str(user["_id"]),
            username=user["username"],
            full_name=user["full_name"],
            email=user["email"],
            role=user["role"],
            created_at=user["created_at"]
        )
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=current_user["_id"],
        username=current_user["username"],
        full_name=current_user["full_name"],
        email=current_user["email"],
        role=current_user["role"],
        created_at=current_user["created_at"]
    )

# ============= Builder Routes =============
@api_router.get("/builders", response_model=List[BuilderResponse])
async def get_builders(
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    builders = await db.builders.find().sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [
        BuilderResponse(
            id=str(b["_id"]),
            builder_name=b["builder_name"],
            company_name=b["company_name"],
            phone=b["phone"],
            address=b.get("address"),
            created_at=b["created_at"]
        )
        for b in builders
    ]

@api_router.post("/builders", response_model=BuilderResponse)
async def create_builder(builder: BuilderCreate, current_user: dict = Depends(get_current_user)):
    builder_dict = builder.dict()
    builder_dict["created_at"] = datetime.utcnow()
    
    result = await db.builders.insert_one(builder_dict)
    created = await db.builders.find_one({"_id": result.inserted_id})
    
    return BuilderResponse(
        id=str(created["_id"]),
        builder_name=created["builder_name"],
        company_name=created["company_name"],
        phone=created["phone"],
        address=created.get("address"),
        created_at=created["created_at"]
    )

@api_router.get("/builders/{builder_id}", response_model=BuilderResponse)
async def get_builder(builder_id: str, current_user: dict = Depends(get_current_user)):
    builder = await db.builders.find_one({"_id": ObjectId(builder_id)})
    if not builder:
        raise HTTPException(status_code=404, detail="Builder not found")
    
    return BuilderResponse(
        id=str(builder["_id"]),
        builder_name=builder["builder_name"],
        company_name=builder["company_name"],
        phone=builder["phone"],
        address=builder.get("address"),
        created_at=builder["created_at"]
    )

@api_router.put("/builders/{builder_id}", response_model=BuilderResponse)
async def update_builder(builder_id: str, builder: BuilderCreate, current_user: dict = Depends(get_current_user)):
    result = await db.builders.update_one(
        {"_id": ObjectId(builder_id)},
        {"$set": builder.dict()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Builder not found")
    
    updated = await db.builders.find_one({"_id": ObjectId(builder_id)})
    return BuilderResponse(
        id=str(updated["_id"]),
        builder_name=updated["builder_name"],
        company_name=updated["company_name"],
        phone=updated["phone"],
        address=updated.get("address"),
        created_at=updated["created_at"]
    )

@api_router.delete("/builders/{builder_id}")
async def delete_builder(builder_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.builders.delete_one({"_id": ObjectId(builder_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Builder not found")
    return {"message": "Builder deleted successfully"}

# ============= Lead Routes =============
@api_router.get("/leads", response_model=List[LeadResponse])
async def get_leads(
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    leads = await db.leads.find().sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [
        LeadResponse(
            id=str(lead["_id"]),
            name=lead["name"],
            email=lead.get("email"),
            phone=lead.get("phone"),
            lead_type=lead.get("lead_type"),
            location=lead.get("location"),
            address=lead.get("address"),
            bhk=lead.get("bhk"),
            budget_min=lead.get("budget_min"),
            budget_max=lead.get("budget_max"),
            property_type=lead.get("property_type"),
            lead_status=lead.get("lead_status"),
            lead_temperature=lead.get("lead_temperature"),
            notes=lead.get("notes"),
            builder_id=lead.get("builder_id"),
            next_followup_date=lead.get("next_followup_date"),
            created_at=lead["created_at"],
            created_by=lead.get("created_by")
        )
        for lead in leads
    ]

@api_router.post("/leads", response_model=LeadResponse)
async def create_lead(lead: LeadCreate, current_user: dict = Depends(get_current_user)):
    lead_dict = lead.dict()
    lead_dict["created_at"] = datetime.utcnow()
    lead_dict["created_by"] = current_user["_id"]
    
    result = await db.leads.insert_one(lead_dict)
    created = await db.leads.find_one({"_id": result.inserted_id})
    
    return LeadResponse(
        id=str(created["_id"]),
        name=created["name"],
        email=created.get("email"),
        phone=created.get("phone"),
        lead_type=created.get("lead_type"),
        location=created.get("location"),
        address=created.get("address"),
        bhk=created.get("bhk"),
        budget_min=created.get("budget_min"),
        budget_max=created.get("budget_max"),
        property_type=created.get("property_type"),
        lead_status=created.get("lead_status"),
        lead_temperature=created.get("lead_temperature"),
        notes=created.get("notes"),
        builder_id=created.get("builder_id"),
        next_followup_date=created.get("next_followup_date"),
        created_at=created["created_at"],
        created_by=created.get("created_by")
    )

@api_router.get("/leads/{lead_id}", response_model=LeadResponse)
async def get_lead(lead_id: str, current_user: dict = Depends(get_current_user)):
    lead = await db.leads.find_one({"_id": ObjectId(lead_id)})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    
    return LeadResponse(
        id=str(lead["_id"]),
        name=lead["name"],
        email=lead.get("email"),
        phone=lead.get("phone"),
        lead_type=lead.get("lead_type"),
        location=lead.get("location"),
        address=lead.get("address"),
        bhk=lead.get("bhk"),
        budget_min=lead.get("budget_min"),
        budget_max=lead.get("budget_max"),
        property_type=lead.get("property_type"),
        lead_status=lead.get("lead_status"),
        lead_temperature=lead.get("lead_temperature"),
        notes=lead.get("notes"),
        builder_id=lead.get("builder_id"),
        next_followup_date=lead.get("next_followup_date"),
        created_at=lead["created_at"],
        created_by=lead.get("created_by")
    )

@api_router.put("/leads/{lead_id}", response_model=LeadResponse)
async def update_lead(lead_id: str, lead: LeadCreate, current_user: dict = Depends(get_current_user)):
    result = await db.leads.update_one(
        {"_id": ObjectId(lead_id)},
        {"$set": lead.dict()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Lead not found")
    
    updated = await db.leads.find_one({"_id": ObjectId(lead_id)})
    return LeadResponse(
        id=str(updated["_id"]),
        name=updated["name"],
        email=updated.get("email"),
        phone=updated.get("phone"),
        lead_type=updated.get("lead_type"),
        location=updated.get("location"),
        address=updated.get("address"),
        bhk=updated.get("bhk"),
        budget_min=updated.get("budget_min"),
        budget_max=updated.get("budget_max"),
        property_type=updated.get("property_type"),
        lead_status=updated.get("lead_status"),
        lead_temperature=updated.get("lead_temperature"),
        notes=updated.get("notes"),
        builder_id=updated.get("builder_id"),
        next_followup_date=updated.get("next_followup_date"),
        created_at=updated["created_at"],
        created_by=updated.get("created_by")
    )

@api_router.delete("/leads/{lead_id}")
async def delete_lead(lead_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.leads.delete_one({"_id": ObjectId(lead_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Lead not found")
    return {"message": "Lead deleted successfully"}

# ============= Reminder Routes =============
@api_router.get("/reminders", response_model=List[ReminderResponse])
async def get_reminders(
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    reminders = await db.reminders.find().sort("reminder_date", 1).skip(skip).limit(limit).to_list(limit)
    return [
        ReminderResponse(
            id=str(r["_id"]),
            lead_id=r.get("lead_id"),
            title=r["title"],
            reminder_date=r["reminder_date"],
            reminder_type=r["reminder_type"],
            notes=r.get("notes"),
            status=r.get("status", "pending"),
            send_whatsapp=r.get("send_whatsapp", False),
            whatsapp_message=r.get("whatsapp_message"),
            created_by=r.get("created_by"),
            created_at=r["created_at"],
            notified=r.get("notified", False)
        )
        for r in reminders
    ]

@api_router.post("/reminders", response_model=ReminderResponse)
async def create_reminder(reminder: ReminderCreate, current_user: dict = Depends(get_current_user)):
    reminder_dict = reminder.dict()
    reminder_dict["created_at"] = datetime.utcnow()
    reminder_dict["created_by"] = current_user["_id"]
    reminder_dict["status"] = "pending"
    reminder_dict["notified"] = False
    
    result = await db.reminders.insert_one(reminder_dict)
    created = await db.reminders.find_one({"_id": result.inserted_id})
    
    # If WhatsApp is enabled, send message (mock for now)
    if created.get("send_whatsapp") and created.get("lead_id"):
        lead = await db.leads.find_one({"_id": ObjectId(created["lead_id"])})
        if lead and lead.get("phone"):
            await send_whatsapp_message_internal(
                lead["phone"],
                created.get("whatsapp_message", f"Reminder: {created['title']}"),
                created["lead_id"]
            )
    
    return ReminderResponse(
        id=str(created["_id"]),
        lead_id=created.get("lead_id"),
        title=created["title"],
        reminder_date=created["reminder_date"],
        reminder_type=created["reminder_type"],
        notes=created.get("notes"),
        status=created.get("status"),
        send_whatsapp=created.get("send_whatsapp", False),
        whatsapp_message=created.get("whatsapp_message"),
        created_by=created.get("created_by"),
        created_at=created["created_at"],
        notified=created.get("notified", False)
    )

@api_router.put("/reminders/{reminder_id}", response_model=ReminderResponse)
async def update_reminder(reminder_id: str, reminder: ReminderCreate, current_user: dict = Depends(get_current_user)):
    result = await db.reminders.update_one(
        {"_id": ObjectId(reminder_id)},
        {"$set": reminder.dict()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Reminder not found")
    
    updated = await db.reminders.find_one({"_id": ObjectId(reminder_id)})
    return ReminderResponse(
        id=str(updated["_id"]),
        lead_id=updated.get("lead_id"),
        title=updated["title"],
        reminder_date=updated["reminder_date"],
        reminder_type=updated["reminder_type"],
        notes=updated.get("notes"),
        status=updated.get("status"),
        send_whatsapp=updated.get("send_whatsapp", False),
        whatsapp_message=updated.get("whatsapp_message"),
        created_by=updated.get("created_by"),
        created_at=updated["created_at"],
        notified=updated.get("notified", False)
    )

@api_router.delete("/reminders/{reminder_id}")
async def delete_reminder(reminder_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.reminders.delete_one({"_id": ObjectId(reminder_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Reminder not found")
    return {"message": "Reminder deleted successfully"}

# ============= WhatsApp Routes (Mock) =============
async def send_whatsapp_message_internal(phone: str, message: str, lead_id: Optional[str] = None):
    """Internal function to send WhatsApp (mock implementation)"""
    log_data = {
        "phone": phone,
        "message": message,
        "lead_id": lead_id,
        "status": "sent",  # Mock: always successful
        "created_at": datetime.utcnow()
    }
    await db.whatsapp_logs.insert_one(log_data)
    return True

@api_router.post("/whatsapp/send")
async def send_whatsapp(data: WhatsAppMessageCreate, current_user: dict = Depends(get_current_user)):
    """Send WhatsApp message (mock implementation)"""
    await send_whatsapp_message_internal(data.phone, data.message, data.lead_id)
    return {"message": "WhatsApp message sent successfully", "status": "sent"}

@api_router.get("/whatsapp/logs", response_model=List[WhatsAppLogResponse])
async def get_whatsapp_logs(current_user: dict = Depends(get_current_user)):
    logs = await db.whatsapp_logs.find().sort("created_at", -1).limit(100).to_list(100)
    return [
        WhatsAppLogResponse(
            id=str(log["_id"]),
            phone=log["phone"],
            message=log["message"],
            lead_id=log.get("lead_id"),
            status=log["status"],
            created_at=log["created_at"]
        )
        for log in logs
    ]

# ============= Dashboard Route =============
@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    total_leads = await db.leads.count_documents({})
    hot_leads = await db.leads.count_documents({"lead_temperature": "Hot"})
    warm_leads = await db.leads.count_documents({"lead_temperature": "Warm"})
    cold_leads = await db.leads.count_documents({"lead_temperature": "Cold"})
    total_builders = await db.builders.count_documents({})
    
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999999)
    today_reminders = await db.reminders.count_documents({
        "reminder_date": {"$gte": today_start, "$lte": today_end}
    })
    pending_reminders = await db.reminders.count_documents({"status": "pending"})
    
    return DashboardStats(
        total_leads=total_leads,
        hot_leads=hot_leads,
        warm_leads=warm_leads,
        cold_leads=cold_leads,
        total_builders=total_builders,
        today_reminders=today_reminders,
        pending_reminders=pending_reminders
    )

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()