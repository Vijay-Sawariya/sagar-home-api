from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, File, UploadFile, Form, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pathlib import Path
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict
from datetime import datetime, timedelta, date
from passlib.context import CryptContext
import jwt
import pymysql
from pymysql.cursors import DictCursor
from contextlib import contextmanager
import re
import base64
import asyncio
import json
import csv
import io

# Import for AI features
try:
    from emergentintegrations.llm.chat import LlmChat, UserMessage
except ModuleNotFoundError:
    LlmChat = None
    UserMessage = None

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Phone/Address masking helper functions
def mask_phone(phone: str) -> str:
    """Mask phone number showing first 2 and last 2 digits"""
    if not phone:
        return phone
    # Remove all non-numeric characters for masking
    clean_phone = re.sub(r'[^0-9]', '', phone)
    if len(clean_phone) <= 4:
        return phone
    # Show first 2 and last 2 digits, mask the rest
    masked = clean_phone[:2] + 'X' * (len(clean_phone) - 4) + clean_phone[-2:]
    return masked

def mask_address(address: str) -> str:
    """Mask address - show only area/locality, hide specific details"""
    if not address:
        return address
    # Mask specific plot/house numbers but keep general area
    # Pattern: hide numbers like C-10, A-123, Plot-5, etc.
    masked = re.sub(r'\b[A-Za-z]?-?\d+[A-Za-z]?\b', '***', address)
    return masked

def should_mask_data(user_role: str, user_id: int, created_by: int) -> bool:
    """Determine if data should be masked based on user role and ownership"""
    # Admin can see everything
    if user_role and user_role.lower() == 'admin':
        return False
    # Owner can see their own data
    if created_by is not None and user_id == created_by:
        return False
    # Everyone else gets masked data
    return True

def apply_lead_masking(lead: dict, user_role: str, user_id: int) -> dict:
    """Apply masking to a lead based on user permissions"""
    created_by = lead.get('created_by')
    if should_mask_data(user_role, user_id, created_by):
        if lead.get('phone'):
            lead['phone'] = mask_phone(lead['phone'])
        if lead.get('address'):
            lead['address'] = mask_address(lead['address'])
    return lead

# MySQL connection config
MYSQL_CONFIG = {
    'host': os.environ.get('MYSQL_HOST'),
    'port': int(os.environ.get('MYSQL_PORT', 3306)),
    'user': os.environ.get('MYSQL_USER'),
    'password': os.environ.get('MYSQL_PASSWORD'),
    'database': os.environ.get('MYSQL_DATABASE'),
    'charset': 'utf8mb4',
    'cursorclass': DictCursor
}

# Security
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI()
api_router = APIRouter(prefix="/api")

# Root health check endpoint for Kubernetes
@app.get("/")
def root_health():
    return {"status": "healthy", "service": "Sagar Home LMS API"}

# API health check endpoint
@api_router.get("/health")
def api_health():
    """Health check endpoint for monitoring"""
    try:
        # Test database connection
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}

# ============= Database Helper =============
@contextmanager
def get_db():
    connection = pymysql.connect(**MYSQL_CONFIG)
    try:
        yield connection
    finally:
        connection.close()

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

def ensure_user_permission_columns(cursor):
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN can_export TINYINT(1) DEFAULT 0")
    except Exception:
        pass

def ensure_security_audit_table(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            event_type VARCHAR(100) NOT NULL,
            entity_type VARCHAR(50) NULL,
            entity_id INT NULL,
            details TEXT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_security_audit_created_at (created_at),
            INDEX idx_security_audit_user_id (user_id),
            INDEX idx_security_audit_event_type (event_type)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

def log_security_event(cursor, user_id, event_type, entity_type=None, entity_id=None, details=None):
    try:
        ensure_security_audit_table(cursor)
        details_text = details if isinstance(details, str) else json.dumps(details or {})
        cursor.execute("""
            INSERT INTO security_audit_logs (user_id, event_type, entity_type, entity_id, details, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """, (user_id, event_type, entity_type, entity_id, details_text))
    except Exception as exc:
        logging.warning(f"Security audit log skipped: {exc}")

def user_can_export(cursor, current_user: dict) -> bool:
    if current_user.get('role') == 'admin':
        return True
    ensure_user_permission_columns(cursor)
    cursor.execute("SELECT can_export FROM users WHERE id = %s", (current_user['id'],))
    result = cursor.fetchone()
    return bool(result and result.get('can_export'))

# ============= Calculation Helper Functions =============
def normalize_floor_label(label: str) -> str:
    """Normalize floor labels for consistent matching"""
    mapping = {
        'T': 'TF', 'F+TT': 'TF+TT', 'TF+TT': 'TF+TT',
        'BASEMENT': 'BMT', 'BAS': 'BMT', 'B': 'BMT'
    }
    upper = label.strip().upper()
    return mapping.get(upper, upper)

def floor_share_percent(label: str) -> Optional[float]:
    """Get floor share percentage for circle value calculation"""
    n = normalize_floor_label(label)
    # Remove any spaces around + sign for consistent matching
    n = n.replace(' + ', '+').replace('+ ', '+').replace(' +', '+')
    
    if n == 'BMT+GF':
        return 32.5
    twenty_two = ['FF', 'SF', 'T', 'TF', 'F+TT', 'TF+TT', 'TF+TERR']
    if n in twenty_two:
        return 22.5
    return None

def norms_from_bucket(plot_sqm: float) -> dict:
    """Get FAR and Coverage norms based on plot size in sq meters"""
    # [min, max, FAR, coverage%]
    rows = [
        (0, 32, 350, 90),
        (32, 50, 350, 90),
        (50, 100, 350, 90),
        (100, 250, 300, 75),
        (250, 750, 225, 75),
        (750, 1000, 250, 50),
        (1000, 1500, 200, 50),
        (1500, 2250, 250, 50),
        (2250, 3000, 200, 50),
        (3000, 3750, 200, 50),
        (3750, float('inf'), 200, 50),
    ]
    for min_val, max_val, far, cov in rows:
        if plot_sqm < 32 and max_val == 32:
            return {'far': far, 'cov': cov}
        if min_val <= plot_sqm <= max_val:
            return {'far': far, 'cov': cov}
    return {'far': 200, 'cov': 50}

def to_sq_meter(value: float, unit: str) -> float:
    """Convert area to square meters"""
    if unit == 'sqm':
        return value
    elif unit == 'sq_yd':
        return value * 0.83612736
    elif unit == 'sq_ft':
        return value / 10.764
    return value

def calculate_circle_values(location: str, area_size: float, floors_str: str, conn) -> List[Dict]:
    """Calculate circle value for each floor"""
    circle_values = []
    
    # Get circle rate from location table (column name has space: "Circle Rate")
    cursor = conn.cursor()
    cursor.execute("SELECT `Circle Rate` as circle_rate FROM locations WHERE LOWER(name) = LOWER(%s)", (location,))
    result = cursor.fetchone()
    
    if not result or not result['circle_rate']:
        return []
    
    circle_rate_per_sqm = float(result['circle_rate'])
    
    # Constants
    construction_cost_per_100_sqyd = 10000000.0  # 1 Crore per 100 sq yd
    sqyd_to_sqm = 0.83612736
    construction_cost_per_sqyd = construction_cost_per_100_sqyd / 100.0
    construction_cost_per_sqm = construction_cost_per_sqyd / sqyd_to_sqm
    
    # Convert area to sq meters (assuming sq_yd as default)
    area_sqm = to_sq_meter(area_size, 'sq_yd')
    
    # Parse floors
    if not floors_str:
        return []
    
    floors = [f.strip() for f in floors_str.split(',') if f.strip()]
    
    for floor in floors:
        share = floor_share_percent(floor)
        if share is not None:
            value = (circle_rate_per_sqm + construction_cost_per_sqm) * area_sqm * (share / 100.0)
            circle_values.append({
                'label': floor,
                'percent': share,
                'value': round(value / 10000000, 2),  # Convert to Crores
            })
    
    return circle_values

def calculate_plot_specifications(area_size: float, floors_count: int, unit: str = 'sq_yd') -> Dict:
    """Calculate plot size specifications"""
    # Convert to sq ft
    if unit == 'sqm':
        plot_sqft = area_size * 10.764
        plot_sqm = area_size
    elif unit == 'sq_yd':
        plot_sqft = area_size * 9
        plot_sqm = area_size * 0.83612736
    else:  # sq_ft
        plot_sqft = area_size
        plot_sqm = area_size / 10.764
    
    # Get FAR and Coverage norms
    norms = norms_from_bucket(plot_sqm)
    far = norms['far']
    cov = norms['cov']
    
    # Calculate total built-up (FAR-based)
    if unit == 'sqm':
        total_builtup_sqft = plot_sqft * far / 100
    else:  # sq_yd or sq_ft
        total_builtup_sqft = plot_sqft * far / 100
    
    # Calculate per-floor built-up
    if floors_count > 0:
        ideal_per_floor = total_builtup_sqft / floors_count
        ground_coverage_sqft = plot_sqft * (cov / 100)
        per_floor_builtup = min(ideal_per_floor, ground_coverage_sqft) + 200
    else:
        per_floor_builtup = 0
    
    return {
        'total_builtup': round(total_builtup_sqft, 2),
        'per_floor_builtup': round(per_floor_builtup, 2),
        'far': far,
        'coverage': cov,
    }

def parse_floor_pricing_from_notes(notes: str) -> Dict[str, float]:
    """Parse floor pricing from notes field"""
    floor_pricing = {}
    if not notes:
        return floor_pricing
    
    # Look for "Floor Pricing: BMT+GF: ₹50000000, FF: ₹55000000"
    match = re.search(r'Floor Pricing:\s*(.+?)(?:\n|$)', notes)
    if match:
        pricing_str = match.group(1)
        # Parse each floor pricing
        for item in pricing_str.split(','):
            item = item.strip()
            if ':' in item:
                parts = item.split(':')
                if len(parts) >= 2:
                    floor = parts[0].strip()
                    price_str = parts[1].strip().replace('₹', '').replace(',', '')
                    try:
                        price = float(price_str)
                        floor_pricing[floor] = price / 10000000  # Convert to Crores
                    except ValueError:
                        continue
    
    return floor_pricing

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        logging.error(f"Auth error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

# ============= Models =============
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    email: EmailStr
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str
    email: str
    role: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class LeadResponse(BaseModel):
    id: int
    name: str
    phone: Optional[str] = None
    email: Optional[str] = None
    lead_type: Optional[str] = None
    location: Optional[str] = None
    bhk: Optional[str] = None
    budget_min: Optional[float] = None
    budget_max: Optional[float] = None
    property_type: Optional[str] = None
    lead_temperature: Optional[str] = None
    lead_status: Optional[str] = None
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    builder_id: Optional[int] = None

class LeadCreate(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[str] = None
    lead_type: Optional[str] = "buyer"
    location: Optional[str] = None
    address: Optional[str] = None
    bhk: Optional[str] = None
    budget_min: Optional[float] = None
    budget_max: Optional[float] = None
    property_type: Optional[str] = None
    lead_temperature: Optional[str] = "Hot"
    lead_status: Optional[str] = "New"
    lead_source: Optional[str] = None
    notes: Optional[str] = None
    builder_id: Optional[int] = None
    floor: Optional[str] = None
    area_size: Optional[str] = None
    car_parking_number: Optional[int] = None
    lift_available: Optional[str] = None
    unit: Optional[str] = None
    Property_locationUrl: Optional[str] = None
    building_facing: Optional[str] = None
    possession_on: Optional[str] = None
    # Amenities as comma-separated string
    required_amenities: Optional[str] = None
    # Legacy individual amenity fields (kept for backward compatibility)
    park_facing: Optional[int] = 0
    park_at_rear: Optional[int] = 0
    wide_road: Optional[int] = 0
    peaceful_location: Optional[int] = 0
    main_road: Optional[int] = 0
    corner: Optional[int] = 0
    # Floor pricing (list of dicts)
    floor_pricing: Optional[List[dict]] = None

class BuilderResponse(BaseModel):
    id: int
    builder_name: str
    company_name: Optional[str]
    phone: Optional[str]
    address: Optional[str]
    created_at: Optional[datetime]

class BuilderCreate(BaseModel):
    builder_name: str
    company_name: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None

class ReminderResponse(BaseModel):
    id: int
    lead_id: Optional[int]
    title: str
    due_date: str  # Date in YYYY-MM-DD format
    due_time: Optional[str]  # Time in HH:MM:SS format
    action_type: str
    description: Optional[str]
    status: str
    priority: Optional[str]
    outcome: Optional[str]
    is_notified: Optional[int]
    created_at: Optional[datetime]

class ReminderCreate(BaseModel):
    lead_id: Optional[int] = None
    title: str
    reminder_date: str  # ISO format datetime string (YYYY-MM-DDTHH:MM:SS)
    reminder_type: str  # Maps to action_type
    notes: Optional[str] = None  # Maps to description
    status: str = "Pending"
    priority: Optional[str] = "Medium"

class DashboardStats(BaseModel):
    total_leads: int
    client_leads: int  # buyer, tenant
    inventory_leads: int  # seller, landlord, builder
    hot_leads: int
    warm_leads: int
    cold_leads: int
    total_builders: int
    today_reminders: int
    pending_reminders: int
    # Enhanced stats
    missed_followups: int = 0
    upcoming_followups: int = 0
    leads_this_week: int = 0
    followups_completed_this_week: int = 0
    leads_converted_this_week: int = 0
    # Lead funnel stats
    new_leads: int = 0
    contacted_leads: int = 0
    qualified_leads: int = 0
    negotiating_leads: int = 0
    won_leads: int = 0
    # Daily usability stats
    uncontacted_new_leads: int = 0
    today_site_visits: int = 0
    stale_leads: int = 0
    available_inventory: int = 0

class AIMatchResult(BaseModel):
    buyer_id: int
    buyer_name: str
    inventory_id: int
    inventory_name: str
    location: str
    match_score: int
    match_reasons: List[str]

class AIMessageRequest(BaseModel):
    lead_id: int
    message_type: str  # first_contact, follow_up, negotiation, closing
    custom_context: Optional[str] = None

class AIMessageResponse(BaseModel):
    message: str
    lead_name: str
    message_type: str

class PreferredLeadsRequest(BaseModel):
    matching_lead_ids: List[int]

# ============= Auth Routes =============
@api_router.post("/auth/register", response_model=UserResponse)
def register(user_data: UserCreate):
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE username = %s", (user_data.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Create user
        hashed_password = get_password_hash(user_data.password)
        cursor.execute(
            "INSERT INTO users (username, password, full_name, email, role, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_data.username, hashed_password, user_data.full_name, user_data.email, user_data.role, datetime.utcnow())
        )
        conn.commit()
        user_id = cursor.lastrowid
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
    return UserResponse(**user)

@api_router.post("/auth/login", response_model=TokenResponse)
def login(credentials: UserLogin):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (credentials.username,))
        user = cursor.fetchone()

        if not user:
            log_security_event(cursor, None, "login_failed", "user", None, {
                "username": credentials.username,
                "reason": "unknown_user"
            })
            conn.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Check if password is hashed (starts with $2b$ for bcrypt) or plain text
        password_valid = False
        if user['password'].startswith('$2b$') or user['password'].startswith('$2a$'):
            # Hashed password - use bcrypt verification
            password_valid = verify_password(credentials.password, user['password'])
        else:
            # Plain text password (legacy) - direct comparison
            password_valid = (credentials.password == user['password'])

        if not password_valid:
            log_security_event(cursor, user['id'], "login_failed", "user", user['id'], {
                "username": credentials.username,
                "reason": "invalid_password"
            })
            conn.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        access_token = create_access_token(data={"sub": str(user['id'])})
        log_security_event(cursor, user['id'], "login_success", "user", user['id'])
        conn.commit()

        return TokenResponse(
            access_token=access_token,
            user=UserResponse(**user)
        )

@api_router.get("/auth/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

# ============= Lead Scoring Helper Functions =============
def calculate_lead_score(lead: dict, last_followup_date: Optional[date] = None) -> dict:
    """
    Calculate lead score based on multiple factors:
    - Recency: How recently the lead was contacted
    - Temperature: Hot/Warm/Cold preference
    - Budget: Higher budget = higher priority
    - Engagement: Based on followup history
    
    Returns a dict with score (0-100) and score breakdown
    """
    score = 0
    breakdown = []
    
    today = datetime.utcnow().date()
    
    # 1. Temperature Score (0-30 points)
    temp = lead.get('lead_temperature', '')
    if temp == 'Hot':
        score += 30
        breakdown.append(('Temperature', 30, 'Hot lead'))
    elif temp == 'Warm':
        score += 20
        breakdown.append(('Temperature', 20, 'Warm lead'))
    elif temp == 'Cold':
        score += 5
        breakdown.append(('Temperature', 5, 'Cold lead'))
    
    # 2. Recency Score (0-25 points) - Based on last contact
    days_since_contact = None
    if last_followup_date:
        days_since_contact = (today - last_followup_date).days
        if days_since_contact <= 2:
            score += 25
            breakdown.append(('Recency', 25, f'Contacted {days_since_contact}d ago'))
        elif days_since_contact <= 7:
            score += 20
            breakdown.append(('Recency', 20, f'Contacted {days_since_contact}d ago'))
        elif days_since_contact <= 14:
            score += 12
            breakdown.append(('Recency', 12, f'Contacted {days_since_contact}d ago'))
        elif days_since_contact <= 30:
            score += 5
            breakdown.append(('Recency', 5, f'Contacted {days_since_contact}d ago'))
        else:
            breakdown.append(('Recency', 0, f'No contact for {days_since_contact}d'))
    else:
        # Check created_at if no followup
        created_at = lead.get('created_at')
        if created_at:
            if isinstance(created_at, str):
                created_date = datetime.strptime(created_at[:10], '%Y-%m-%d').date()
            else:
                created_date = created_at.date() if hasattr(created_at, 'date') else created_at
            days_since_created = (today - created_date).days
            if days_since_created <= 3:
                score += 15
                breakdown.append(('Recency', 15, f'New lead ({days_since_created}d old)'))
            else:
                breakdown.append(('Recency', 0, 'Never contacted'))
        else:
            breakdown.append(('Recency', 0, 'Never contacted'))
    
    # 3. Budget Score (0-20 points)
    budget_max = lead.get('budget_max') or lead.get('budget_min') or 0
    if budget_max:
        budget_max = float(budget_max)
        if budget_max >= 5:  # 5 Cr+
            score += 20
            breakdown.append(('Budget', 20, f'High budget (₹{budget_max}Cr)'))
        elif budget_max >= 2:  # 2-5 Cr
            score += 15
            breakdown.append(('Budget', 15, f'Medium budget (₹{budget_max}Cr)'))
        elif budget_max >= 1:  # 1-2 Cr
            score += 10
            breakdown.append(('Budget', 10, f'Standard budget (₹{budget_max}Cr)'))
        else:
            score += 5
            breakdown.append(('Budget', 5, f'Entry budget (₹{budget_max}Cr)'))
    
    # 4. Lead Status Score (0-15 points)
    status = lead.get('lead_status', '')
    if status in ['Negotiating', 'Site Visit Done']:
        score += 15
        breakdown.append(('Status', 15, f'{status}'))
    elif status in ['Qualified', 'Interested']:
        score += 12
        breakdown.append(('Status', 12, f'{status}'))
    elif status in ['Contacted', 'Follow Up']:
        score += 8
        breakdown.append(('Status', 8, f'{status}'))
    elif status == 'New':
        score += 5
        breakdown.append(('Status', 5, 'New lead'))
    
    # 5. Completeness Score (0-10 points)
    completeness = 0
    if lead.get('phone'):
        completeness += 2
    if lead.get('location'):
        completeness += 2
    if lead.get('budget_min') or lead.get('budget_max'):
        completeness += 2
    if lead.get('bhk'):
        completeness += 2
    if lead.get('floor'):
        completeness += 2
    score += completeness
    breakdown.append(('Completeness', completeness, f'{completeness}/10 fields'))
    
    return {
        'score': min(score, 100),
        'days_since_contact': days_since_contact,
        'breakdown': breakdown
    }

def get_aging_label(days: Optional[int]) -> dict:
    """Get aging indicator label and color based on days since contact"""
    if days is None:
        return {'label': 'Never contacted', 'color': 'gray', 'urgency': 'unknown'}
    elif days <= 2:
        return {'label': f'{days}d ago', 'color': 'green', 'urgency': 'recent'}
    elif days <= 7:
        return {'label': f'{days}d ago', 'color': 'blue', 'urgency': 'good'}
    elif days <= 14:
        return {'label': f'{days}d ago', 'color': 'orange', 'urgency': 'attention'}
    elif days <= 30:
        return {'label': f'{days}d ago', 'color': 'red', 'urgency': 'overdue'}
    else:
        return {'label': f'{days}d ago', 'color': 'darkred', 'urgency': 'critical'}

# ============= Lead Routes =============
@api_router.get("/leads/clients")
def get_client_leads(
    skip: int = 0,
    limit: int = 1000,
    current_user: dict = Depends(get_current_user)
):
    """Get CLIENT leads (buyer, tenant) - excludes deleted, includes next action/followup and lead scoring"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT l.*, u.full_name as created_by_name 
               FROM leads l
               LEFT JOIN users u ON l.created_by = u.id
               WHERE l.lead_type IN ('buyer', 'tenant') 
               AND (l.is_deleted IS NULL OR l.is_deleted = 0)
               ORDER BY l.created_at DESC LIMIT %s OFFSET %s""",
            (limit, skip)
        )
        leads = cursor.fetchall()
        
        if leads:
            lead_ids = [lead['id'] for lead in leads]
            placeholders = ','.join(['%s'] * len(lead_ids))
            
            # Fetch next pending action/followup for each lead
            cursor.execute(
                f"""SELECT lead_id, due_date, due_time, title, status
                    FROM actions 
                    WHERE lead_id IN ({placeholders}) 
                    AND status IN ('Pending', 'Missed', 'Up Coming')
                    ORDER BY due_date ASC, due_time ASC""",
                lead_ids
            )
            all_actions = cursor.fetchall()
            
            # Group actions by lead_id and get the earliest one
            action_map = {}
            for a in all_actions:
                lead_id = a['lead_id']
                if lead_id not in action_map:
                    action_map[lead_id] = a
            
            # Fetch last followup date for each lead (for aging/scoring)
            cursor.execute(
                f"""SELECT lead_id, MAX(followup_date) as last_followup_date
                    FROM followups
                    WHERE lead_id IN ({placeholders})
                    AND (is_deleted IS NULL OR is_deleted = 0)
                    GROUP BY lead_id""",
                lead_ids
            )
            last_followups = cursor.fetchall()
            followup_map = {f['lead_id']: f['last_followup_date'] for f in last_followups}
            
            # Add next_action and scoring to each lead
            for lead in leads:
                lead_id = lead['id']
                
                # Add next action
                if lead_id in action_map:
                    action = action_map[lead_id]
                    lead['next_action_date'] = str(action['due_date']) if action['due_date'] else None
                    lead['next_action_time'] = str(action['due_time']) if action['due_time'] else None
                    lead['next_action_title'] = action['title']
                    lead['next_action_status'] = action['status']
                
                # Calculate lead score and aging
                last_contact_date = followup_map.get(lead_id)
                score_data = calculate_lead_score(lead, last_contact_date)
                
                lead['lead_score'] = score_data['score']
                lead['days_since_contact'] = score_data['days_since_contact']
                lead['score_breakdown'] = score_data['breakdown']
                
                # Add aging indicator
                aging = get_aging_label(score_data['days_since_contact'])
                lead['aging_label'] = aging['label']
                lead['aging_color'] = aging['color']
                lead['aging_urgency'] = aging['urgency']
    
    # Apply masking based on user permissions
    user_role = current_user.get('role', '')
    user_id = current_user.get('id')
    masked_leads = [apply_lead_masking(dict(lead), user_role, user_id) for lead in leads]
    
    return masked_leads

@api_router.get("/leads/{lead_id}/preferred-inventory")
def get_preferred_inventory_ids(
    lead_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get list of preferred/matched inventory IDs for a client lead"""
    with get_db() as conn:
        cursor = conn.cursor()
        # Get all matching_lead_id from preferred_leads for this client
        cursor.execute(
            """SELECT matching_lead_id 
               FROM preferred_leads 
               WHERE lead_id = %s AND matching_lead_id IS NOT NULL""",
            (lead_id,)
        )
        rows = cursor.fetchall()
    
    # Return list of inventory IDs
    inventory_ids = [row['matching_lead_id'] for row in rows]
    return {"client_id": lead_id, "preferred_inventory_ids": inventory_ids}

def _split_csv(value) -> List[str]:
    return [item.strip() for item in str(value or '').split(',') if item and item.strip()]

def _normalize_floor_token(value) -> str:
    token = str(value or '').strip().lower()
    token = re.sub(r'\s*\+\s*', '+', token)
    token = re.sub(r'\s+', ' ', token)
    return token

def _normalize_floor_list(values) -> List[str]:
    tokens = []
    for value in values or []:
        for part in str(value or '').split(','):
            token = _normalize_floor_token(part)
            if token and token not in tokens:
                tokens.append(token)
    return tokens

def _parse_multi_param(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        raw_values = value
    else:
        raw_values = str(value).split(',')
    return [str(v).strip() for v in raw_values if str(v).strip()]

def _float_or_none(value):
    try:
        if value is None or value == '':
            return None
        return float(value)
    except (TypeError, ValueError):
        return None

def _lead_price_range(lead: dict, floor_pricing: Optional[List[dict]] = None, selected_floors: Optional[List[str]] = None):
    prices = []
    selected_tokens = set(_normalize_floor_list(selected_floors or []))
    for row in floor_pricing or []:
        label = row.get('floor_label')
        if selected_tokens and _normalize_floor_token(label) not in selected_tokens:
            continue
        amount = _float_or_none(row.get('floor_amount'))
        if amount and amount > 0:
            prices.append(amount)
    if prices:
        return min(prices), max(prices)

    budget_min = _float_or_none(lead.get('budget_min'))
    budget_max = _float_or_none(lead.get('budget_max'))
    if budget_min is None and budget_max is None:
        return None, None
    if budget_min is None:
        budget_min = budget_max
    if budget_max is None:
        budget_max = budget_min
    return budget_min, budget_max

def _ranges_overlap(min_a, max_a, min_b, max_b) -> bool:
    if min_a is None and max_a is None:
        return True
    if min_b is None and max_b is None:
        return True
    a_min = min_a if min_a is not None else max_a
    a_max = max_a if max_a is not None else min_a
    b_min = min_b if min_b is not None else max_b
    b_max = max_b if max_b is not None else min_b
    return float(a_max) >= float(b_min) and float(a_min) <= float(b_max)

def _location_matches(candidate_location: str, selected_locations: List[str]) -> bool:
    if not selected_locations:
        return True
    candidate_locations = [loc.lower() for loc in _split_csv(candidate_location)]
    selected = [loc.lower() for loc in selected_locations]
    return any(
        cand == sel or cand in sel or sel in cand
        for cand in candidate_locations
        for sel in selected
    )

def _floor_matches(candidate_floor: str, selected_floors: List[str]) -> bool:
    selected_tokens = set(_normalize_floor_list(selected_floors))
    if not selected_tokens:
        return True
    candidate_tokens = set(_normalize_floor_list([candidate_floor]))
    return not candidate_tokens or bool(candidate_tokens.intersection(selected_tokens))

def _matching_defaults(lead: dict) -> dict:
    area = _float_or_none(lead.get('area_size'))
    budget_min = _float_or_none(lead.get('budget_min'))
    budget_max = _float_or_none(lead.get('budget_max'))
    return {
        "locations": _split_csv(lead.get('location')),
        "floors": _split_csv(lead.get('floor')),
        "area_min": max(0, area - 100) if area is not None else None,
        "area_max": area + 100 if area is not None else None,
        "budget_min": budget_min * 0.8 if budget_min is not None else None,
        "budget_max": budget_max * 1.2 if budget_max is not None else None,
    }

def _get_floor_pricing_map(cursor, lead_ids: List[int]) -> dict:
    if not lead_ids:
        return {}
    placeholders = ','.join(['%s'] * len(lead_ids))
    cursor.execute(
        f"SELECT lead_id, floor_label, floor_amount FROM inventory_floor_pricing WHERE lead_id IN ({placeholders}) ORDER BY lead_id, id",
        lead_ids
    )
    floor_rows = cursor.fetchall()
    pricing = {}
    for row in floor_rows:
        pricing.setdefault(row['lead_id'], []).append({
            'floor_label': row['floor_label'],
            'floor_amount': float(row['floor_amount']) if row['floor_amount'] else 0
        })
    return pricing

@api_router.get("/leads/{lead_id}/matching-inventory")
def get_matching_inventory(
    lead_id: int,
    locations: Optional[str] = None,
    floors: Optional[str] = None,
    area_min: Optional[float] = None,
    area_max: Optional[float] = None,
    budget_min: Optional[float] = None,
    budget_max: Optional[float] = None,
    current_user: dict = Depends(get_current_user)
):
    """Find seller/builder/owner inventory candidates for a buyer/tenant lead."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM leads WHERE id = %s AND (is_deleted IS NULL OR is_deleted = 0)", (lead_id,))
        lead = cursor.fetchone()
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")

        defaults = _matching_defaults(lead)
        selected_locations = _parse_multi_param(locations) or defaults["locations"]
        selected_floors = _parse_multi_param(floors) or defaults["floors"]
        effective_area_min = area_min if area_min is not None else defaults["area_min"]
        effective_area_max = area_max if area_max is not None else defaults["area_max"]
        effective_budget_min = budget_min if budget_min is not None else defaults["budget_min"]
        effective_budget_max = budget_max if budget_max is not None else defaults["budget_max"]

        cursor.execute("""
            SELECT l.*, u.full_name AS created_by_name
            FROM leads l
            LEFT JOIN users u ON u.id = l.created_by
            WHERE l.id != %s
              AND LOWER(IFNULL(l.lead_type, '')) IN ('seller', 'builder', 'landlord', 'owner')
              AND (l.is_deleted IS NULL OR l.is_deleted = 0)
            ORDER BY l.created_at DESC
        """, (lead_id,))
        candidates = cursor.fetchall()
        pricing_map = _get_floor_pricing_map(cursor, [row['id'] for row in candidates])

        cursor.execute(
            "SELECT matching_lead_id FROM preferred_leads WHERE lead_id = %s AND matching_lead_id IS NOT NULL",
            (lead_id,)
        )
        preferred_ids = {row['matching_lead_id'] for row in cursor.fetchall()}

    matches = []
    for row in candidates:
        if not _location_matches(row.get('location'), selected_locations):
            continue
        if not _floor_matches(row.get('floor'), selected_floors):
            continue

        candidate_area = _float_or_none(row.get('area_size'))
        if effective_area_min is not None and candidate_area is not None and candidate_area < effective_area_min:
            continue
        if effective_area_max is not None and candidate_area is not None and candidate_area > effective_area_max:
            continue

        price_min, price_max = _lead_price_range(row, pricing_map.get(row['id'], []), selected_floors)
        if not _ranges_overlap(price_min, price_max, effective_budget_min, effective_budget_max):
            continue

        item = dict(row)
        item['floor_pricing'] = pricing_map.get(row['id'], [])
        item['is_preferred'] = row['id'] in preferred_ids
        item['match_reasons'] = [
            reason for reason, ok in [
                ('Location', bool(selected_locations)),
                ('Floor', bool(selected_floors)),
                ('Area +/- 100 sq yds', effective_area_min is not None or effective_area_max is not None),
                ('Budget +/- 20%', effective_budget_min is not None or effective_budget_max is not None),
            ] if ok
        ]
        # Apply masking based on user permissions
        user_role = current_user.get('role', '')
        user_id = current_user.get('id')
        item = apply_lead_masking(item, user_role, user_id)
        matches.append(item)

    return {"lead_id": lead_id, "defaults": defaults, "filters": {
        "locations": selected_locations,
        "floors": selected_floors,
        "area_min": effective_area_min,
        "area_max": effective_area_max,
        "budget_min": effective_budget_min,
        "budget_max": effective_budget_max,
    }, "matches": matches}

@api_router.get("/leads/{lead_id}/matching-clients")
def get_matching_clients(
    lead_id: int,
    locations: Optional[str] = None,
    floors: Optional[str] = None,
    area_min: Optional[float] = None,
    area_max: Optional[float] = None,
    budget_min: Optional[float] = None,
    budget_max: Optional[float] = None,
    current_user: dict = Depends(get_current_user)
):
    """Find buyer/tenant client candidates for a seller/builder/owner inventory lead."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM leads WHERE id = %s AND (is_deleted IS NULL OR is_deleted = 0)", (lead_id,))
        inventory = cursor.fetchone()
        if not inventory:
            raise HTTPException(status_code=404, detail="Lead not found")

        defaults = _matching_defaults(inventory)
        inventory_pricing = _get_floor_pricing_map(cursor, [lead_id]).get(lead_id, [])
        inv_min, inv_max = _lead_price_range(inventory, inventory_pricing, defaults["floors"])
        if defaults["budget_min"] is None and inv_min is not None:
            defaults["budget_min"] = inv_min * 0.8
        if defaults["budget_max"] is None and inv_max is not None:
            defaults["budget_max"] = inv_max * 1.2

        selected_locations = _parse_multi_param(locations) or defaults["locations"]
        selected_floors = _parse_multi_param(floors) or defaults["floors"]
        effective_area_min = area_min if area_min is not None else defaults["area_min"]
        effective_area_max = area_max if area_max is not None else defaults["area_max"]
        effective_budget_min = budget_min if budget_min is not None else defaults["budget_min"]
        effective_budget_max = budget_max if budget_max is not None else defaults["budget_max"]

        inventory_type = str(inventory.get('lead_type') or '').lower()
        target_types = ['buyer', 'tenant']
        if inventory_type in ['seller', 'builder']:
            target_types = ['buyer']
        elif inventory_type in ['landlord', 'owner']:
            target_types = ['tenant']
        placeholders = ','.join(['%s'] * len(target_types))
        cursor.execute(f"""
            SELECT l.*, u.full_name AS created_by_name
            FROM leads l
            LEFT JOIN users u ON u.id = l.created_by
            WHERE l.id != %s
              AND LOWER(IFNULL(l.lead_type, '')) IN ({placeholders})
              AND (l.is_deleted IS NULL OR l.is_deleted = 0)
            ORDER BY l.created_at DESC
        """, [lead_id, *target_types])
        candidates = cursor.fetchall()

        cursor.execute(
            "SELECT lead_id FROM preferred_leads WHERE matching_lead_id = %s AND lead_id IS NOT NULL",
            (lead_id,)
        )
        preferred_client_ids = {row['lead_id'] for row in cursor.fetchall()}

    matches = []
    for row in candidates:
        if not _location_matches(row.get('location'), selected_locations):
            continue
        if not _floor_matches(row.get('floor'), selected_floors):
            continue

        candidate_area = _float_or_none(row.get('area_size'))
        if effective_area_min is not None and candidate_area is not None and candidate_area < effective_area_min:
            continue
        if effective_area_max is not None and candidate_area is not None and candidate_area > effective_area_max:
            continue

        buyer_min, buyer_max = _lead_price_range(row)
        expanded_min = buyer_min * 0.8 if buyer_min is not None else None
        expanded_max = buyer_max * 1.2 if buyer_max is not None else None
        if not _ranges_overlap(expanded_min, expanded_max, effective_budget_min, effective_budget_max):
            continue

        item = dict(row)
        item['is_preferred'] = row['id'] in preferred_client_ids
        item['match_reasons'] = [
            reason for reason, ok in [
                ('Location', bool(selected_locations)),
                ('Floor', bool(selected_floors)),
                ('Area +/- 100 sq yds', effective_area_min is not None or effective_area_max is not None),
                ('Budget +/- 20%', effective_budget_min is not None or effective_budget_max is not None),
            ] if ok
        ]
        # Apply masking based on user permissions
        user_role = current_user.get('role', '')
        user_id = current_user.get('id')
        item = apply_lead_masking(item, user_role, user_id)
        matches.append(item)

    return {"lead_id": lead_id, "defaults": defaults, "filters": {
        "locations": selected_locations,
        "floors": selected_floors,
        "area_min": effective_area_min,
        "area_max": effective_area_max,
        "budget_min": effective_budget_min,
        "budget_max": effective_budget_max,
    }, "matches": matches}

@api_router.post("/leads/{lead_id}/preferred-leads")
def add_preferred_leads(
    lead_id: int,
    payload: PreferredLeadsRequest,
    current_user: dict = Depends(get_current_user)
):
    """Add checked matching inventory/client rows into preferred_leads."""
    ids = [int(item) for item in payload.matching_lead_ids if int(item) > 0]
    if not ids:
        raise HTTPException(status_code=400, detail="No matching leads selected")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, lead_type FROM leads WHERE id = %s AND (is_deleted IS NULL OR is_deleted = 0)", (lead_id,))
        source = cursor.fetchone()
        if not source:
            raise HTTPException(status_code=404, detail="Lead not found")

        source_type = str(source.get('lead_type') or '').lower()
        inserted = 0
        for match_id in ids:
            if source_type in ['buyer', 'tenant']:
                client_id = lead_id
                inventory_id = match_id
            else:
                client_id = match_id
                inventory_id = lead_id

            cursor.execute(
                "SELECT id FROM preferred_leads WHERE lead_id = %s AND matching_lead_id = %s LIMIT 1",
                (client_id, inventory_id)
            )
            if cursor.fetchone():
                continue

            cursor.execute(
                "INSERT INTO preferred_leads (lead_id, matching_lead_id, reaction, created_at) VALUES (%s, %s, %s, %s)",
                (client_id, inventory_id, 'neutral', datetime.utcnow())
            )
            inserted += 1

        conn.commit()

    return {"success": True, "added": inserted, "selected": len(ids)}

@api_router.get("/leads/inventory")
def get_inventory_leads(
    skip: int = 0,
    limit: int = 1000,
    current_user: dict = Depends(get_current_user)
):
    """Get INVENTORY leads (seller, landlord, builder) with floor pricing, scoring, and aging - excludes deleted"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT l.*, u.full_name as created_by_name 
               FROM leads l
               LEFT JOIN users u ON l.created_by = u.id
               WHERE l.lead_type IN ('seller', 'landlord', 'builder') 
               AND (l.is_deleted IS NULL OR l.is_deleted = 0)
               ORDER BY l.created_at DESC LIMIT %s OFFSET %s""",
            (limit, skip)
        )
        leads = cursor.fetchall()
        
        # Fetch floor pricing for all leads
        if leads:
            lead_ids = [lead['id'] for lead in leads]
            placeholders = ','.join(['%s'] * len(lead_ids))
            cursor.execute(
                f"SELECT * FROM inventory_floor_pricing WHERE lead_id IN ({placeholders}) ORDER BY lead_id, id",
                lead_ids
            )
            all_floor_pricing = cursor.fetchall()
            
            # Group floor pricing by lead_id
            floor_pricing_map = {}
            for fp in all_floor_pricing:
                lead_id = fp['lead_id']
                if lead_id not in floor_pricing_map:
                    floor_pricing_map[lead_id] = []
                floor_pricing_map[lead_id].append({
                    'floor_label': fp['floor_label'],
                    'floor_amount': float(fp['floor_amount']) if fp['floor_amount'] else 0
                })
            
            # Fetch last followup date for each lead (for aging/scoring)
            cursor.execute(
                f"""SELECT lead_id, MAX(followup_date) as last_followup_date
                    FROM followups
                    WHERE lead_id IN ({placeholders})
                    AND (is_deleted IS NULL OR is_deleted = 0)
                    GROUP BY lead_id""",
                lead_ids
            )
            last_followups = cursor.fetchall()
            followup_map = {f['lead_id']: f['last_followup_date'] for f in last_followups}
            
            # Add floor pricing, scoring, and aging to each lead
            for lead in leads:
                lead_id = lead['id']
                lead['floor_pricing'] = floor_pricing_map.get(lead_id, [])
                
                # Calculate lead score and aging
                last_contact_date = followup_map.get(lead_id)
                score_data = calculate_lead_score(lead, last_contact_date)
                
                lead['lead_score'] = score_data['score']
                lead['days_since_contact'] = score_data['days_since_contact']
                lead['score_breakdown'] = score_data['breakdown']
                
                # Add aging indicator
                aging = get_aging_label(score_data['days_since_contact'])
                lead['aging_label'] = aging['label']
                lead['aging_color'] = aging['color']
                lead['aging_urgency'] = aging['urgency']
    
    # Apply masking based on user permissions
    user_role = current_user.get('role', '')
    user_id = current_user.get('id')
    masked_leads = [apply_lead_masking(dict(lead), user_role, user_id) for lead in leads]
    
    return masked_leads

@api_router.get("/leads/search")
def search_leads(q: str, current_user: dict = Depends(get_current_user)):
    """Search leads by name or phone"""
    if len(q) < 2:
        return []
    
    search_term = f"%{q}%"
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, name, phone, email, lead_type, lead_status, location 
               FROM leads 
               WHERE (is_deleted IS NULL OR is_deleted = 0)
               AND (name LIKE %s OR phone LIKE %s OR email LIKE %s)
               ORDER BY name ASC
               LIMIT 10""",
            (search_term, search_term, search_term)
        )
        leads = cursor.fetchall()
    
    return [dict(lead) for lead in leads]

@api_router.get("/leads", response_model=List[LeadResponse])
def get_all_leads(
    skip: int = 0,
    limit: int = 1000,
    current_user: dict = Depends(get_current_user)
):
    """Get all leads - excludes deleted"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM leads 
               WHERE (is_deleted IS NULL OR is_deleted = 0)
               ORDER BY created_at DESC LIMIT %s OFFSET %s""",
            (limit, skip)
        )
        leads = cursor.fetchall()
    
    return [LeadResponse(**lead) for lead in leads]

@api_router.get("/leads/map-data")
def get_leads_for_map(lead_type: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Get leads with location data for map view"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # First check if locations table exists and has latitude/longitude columns
        try:
            cursor.execute("SHOW COLUMNS FROM locations LIKE 'latitude'")
            has_latitude = cursor.fetchone() is not None
            cursor.execute("SHOW COLUMNS FROM locations LIKE 'longitude'")
            has_longitude = cursor.fetchone() is not None
            has_coordinates = has_latitude and has_longitude
        except:
            has_coordinates = False
        
        if has_coordinates:
            query = """
                SELECT l.id, l.name, l.lead_type, l.location, l.address, l.Property_locationUrl,
                       l.budget_min, l.budget_max, l.bhk, l.area_size, loc.latitude, loc.longitude
                FROM leads l
                LEFT JOIN locations loc ON LOWER(l.location) LIKE CONCAT('%%', LOWER(loc.name), '%%')
                WHERE (l.is_deleted IS NULL OR l.is_deleted = 0)
                AND l.location IS NOT NULL AND l.location != ''
            """
        else:
            query = """
                SELECT l.id, l.name, l.lead_type, l.location, l.address, l.Property_locationUrl,
                       l.budget_min, l.budget_max, l.bhk, l.area_size, NULL as latitude, NULL as longitude
                FROM leads l
                WHERE (l.is_deleted IS NULL OR l.is_deleted = 0)
                AND l.location IS NOT NULL AND l.location != ''
            """
        
        params = []
        
        if lead_type:
            query += " AND l.lead_type = %s"
            params.append(lead_type)
        
        query += " LIMIT 100"
        cursor.execute(query, params)
        leads = cursor.fetchall()
        return [dict(l) for l in leads]

@api_router.get("/leads/{lead_id}")
def get_lead(lead_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM leads WHERE id = %s", (lead_id,))
        lead = cursor.fetchone()
        
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        # Fetch floor pricing from database
        cursor.execute(
            "SELECT floor_label, floor_amount FROM inventory_floor_pricing WHERE lead_id = %s ORDER BY id",
            (lead_id,)
        )
        floor_pricing_rows = cursor.fetchall()
        
    # Build floor pricing list
    floor_pricing = []
    for row in floor_pricing_rows:
        floor_pricing.append({
            'floor_label': row['floor_label'],
            'floor_amount': float(row['floor_amount']) if row['floor_amount'] else 0
        })
    
    # Calculate circle values and plot specifications
    calculations = {}
    
    # Only calculate for inventory leads with required data
    if lead.get('lead_type') in ['seller', 'landlord', 'builder'] and lead.get('area_size') and lead.get('location'):
        try:
            # Get floors from the floor column directly
            floors_str = lead.get('floor', '')
            
            # Calculate circle values
            if floors_str:
                with get_db() as conn:
                    circle_values = calculate_circle_values(
                        lead['location'],
                        float(lead['area_size']),
                        floors_str,
                        conn
                    )
                    calculations['circle_values'] = circle_values
                
                # Calculate plot specifications
                floors_count = len([f.strip() for f in floors_str.split(',') if f.strip()])
                plot_specs = calculate_plot_specifications(
                    float(lead['area_size']),
                    floors_count,
                    'sq_yd'  # Default unit
                )
                calculations['plot_specifications'] = plot_specs
            
        except Exception as e:
            logging.error(f"Calculation error for lead {lead_id}: {e}")
            calculations['error'] = str(e)
    
    # Return lead with floor pricing and calculations
    response = dict(lead)
    response['floor_pricing'] = floor_pricing
    response['calculations'] = calculations
    
    # Fetch matched properties for client leads (buyer, tenant)
    if lead.get('lead_type') in ['buyer', 'tenant']:
        with get_db() as conn:
            cursor = conn.cursor()
            # Get matched properties from preferred_leads
            cursor.execute("""
                SELECT 
                    pl.id as match_id,
                    pl.reaction,
                    m.id as property_id,
                    m.name as property_name,
                    m.lead_type as property_type,
                    m.phone as property_phone,
                    m.floor as property_floor,
                    m.bhk as property_bhk,
                    m.area_size as property_size,
                    m.lead_status as property_status,
                    m.location as property_location,
                    m.address as property_address,
                    m.Property_locationUrl as property_map_url,
                    m.notes as property_notes,
                    m.unit as property_unit,
                    m.created_by as property_created_by,
                    u.full_name as created_by_fullname,
                    u.phone as created_by_phone
                FROM preferred_leads pl
                LEFT JOIN leads m ON pl.matching_lead_id = m.id
                LEFT JOIN users u ON m.created_by = u.id
                WHERE pl.lead_id = %s
                ORDER BY pl.created_at DESC
            """, (lead_id,))
            matched_properties = cursor.fetchall()
            
            # Fetch floor pricing for each matched property
            for prop in matched_properties:
                if prop.get('property_id'):
                    cursor.execute(
                        "SELECT floor_label, floor_amount FROM inventory_floor_pricing WHERE lead_id = %s ORDER BY id",
                        (prop['property_id'],)
                    )
                    prop_floor_pricing = cursor.fetchall()
                    prop['floor_pricing'] = [
                        {'floor_label': fp['floor_label'], 'floor_amount': float(fp['floor_amount']) if fp['floor_amount'] else 0}
                        for fp in prop_floor_pricing
                    ]
                else:
                    prop['floor_pricing'] = []
            
            response['matched_properties'] = matched_properties
    else:
        response['matched_properties'] = []
    
    return response

@api_router.post("/leads", response_model=LeadResponse)
def create_lead(lead: LeadCreate, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Build insert query with all available fields
        fields = ['name', 'phone', 'email', 'lead_type', 'location', 'address', 'bhk', 
                  'budget_min', 'budget_max', 'property_type', 'lead_temperature', 'lead_status', 
                  'lead_source', 'notes', 'floor', 'area_size', 'car_parking_number', 'lift_available', 'unit',
                  'Property_locationUrl', 'building_facing', 'possession_on', 'builder_id',
                  'park_facing', 'park_at_rear', 'wide_road', 'peaceful_location', 'main_road', 'corner',
                  'required_amenities', 'created_at', 'created_by']
        
        values_dict = {
            'name': lead.name,
            'phone': lead.phone,
            'email': lead.email,
            'lead_type': lead.lead_type,
            'location': lead.location,
            'address': getattr(lead, 'address', None),
            'bhk': lead.bhk,
            'budget_min': lead.budget_min,
            'budget_max': lead.budget_max,
            'property_type': lead.property_type,
            'lead_temperature': lead.lead_temperature,
            'lead_status': lead.lead_status,
            'lead_source': getattr(lead, 'lead_source', None),
            'notes': lead.notes,
            'floor': getattr(lead, 'floor', None),
            'area_size': getattr(lead, 'area_size', None),
            'car_parking_number': getattr(lead, 'car_parking_number', None),
            'lift_available': getattr(lead, 'lift_available', None),
            'unit': getattr(lead, 'unit', None),
            'Property_locationUrl': getattr(lead, 'Property_locationUrl', None),
            'building_facing': getattr(lead, 'building_facing', None),
            'possession_on': getattr(lead, 'possession_on', None),
            'builder_id': getattr(lead, 'builder_id', None),
            'park_facing': getattr(lead, 'park_facing', 0),
            'park_at_rear': getattr(lead, 'park_at_rear', 0),
            'wide_road': getattr(lead, 'wide_road', 0),
            'peaceful_location': getattr(lead, 'peaceful_location', 0),
            'main_road': getattr(lead, 'main_road', 0),
            'corner': getattr(lead, 'corner', 0),
            'required_amenities': getattr(lead, 'required_amenities', None),
            'created_at': datetime.utcnow(),
            'created_by': current_user['id']
        }
        
        # Filter out None values for optional fields (except required ones)
        insert_fields = []
        insert_values = []
        for field in fields:
            if values_dict[field] is not None or field in ['name', 'created_at', 'created_by']:
                insert_fields.append(field)
                insert_values.append(values_dict[field])
        
        placeholders = ', '.join(['%s'] * len(insert_fields))
        query = f"INSERT INTO leads ({', '.join(insert_fields)}) VALUES ({placeholders})"
        
        cursor.execute(query, insert_values)
        conn.commit()
        lead_id = cursor.lastrowid
        
        # Handle floor pricing if provided
        floor_pricing = getattr(lead, 'floor_pricing', None)
        if floor_pricing:
            for fp in floor_pricing:
                if fp.get('floor') and fp.get('price'):
                    cursor.execute(
                        """INSERT INTO inventory_floor_pricing (lead_id, floor_label, floor_amount)
                           VALUES (%s, %s, %s)""",
                        (lead_id, fp['floor'], float(fp['price']))
                    )
            conn.commit()
        
        cursor.execute("SELECT * FROM leads WHERE id = %s", (lead_id,))
        created = cursor.fetchone()
    
    return LeadResponse(**created)

@api_router.put("/leads/{lead_id}")
def update_lead(lead_id: int, lead_data: dict, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Build dynamic update query based on provided fields
        update_fields = []
        values = []
        
        allowed_fields = [
            'name', 'phone', 'email', 'lead_type', 'location', 'address',
            'bhk', 'budget_min', 'budget_max', 'property_type',
            'lead_temperature', 'lead_status', 'notes', 'floor', 'area_size',
            'car_parking_number', 'lift_available', 'unit', 'Property_locationUrl',
            'building_facing', 'possession_on', 'builder_id',
            'park_facing', 'park_at_rear', 'wide_road', 'peaceful_location', 'main_road', 'corner',
            'required_amenities'
        ]
        
        for field in allowed_fields:
            if field in lead_data:
                update_fields.append(f"{field} = %s")
                values.append(lead_data[field])
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        values.append(lead_id)
        query = f"UPDATE leads SET {', '.join(update_fields)} WHERE id = %s"
        
        cursor.execute(query, values)
        conn.commit()
        
        # Handle floor pricing if provided
        if 'floor_pricing' in lead_data and lead_data['floor_pricing']:
            # Delete existing floor pricing
            cursor.execute("DELETE FROM inventory_floor_pricing WHERE lead_id = %s", (lead_id,))
            
            # Insert new floor pricing
            for fp in lead_data['floor_pricing']:
                if fp.get('floor') and fp.get('price'):
                    cursor.execute(
                        """INSERT INTO inventory_floor_pricing (lead_id, floor_label, floor_amount)
                           VALUES (%s, %s, %s)""",
                        (lead_id, fp['floor'], float(fp['price']))
                    )
            conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        cursor.execute("SELECT * FROM leads WHERE id = %s", (lead_id,))
        updated = cursor.fetchone()
    
    return updated

@api_router.delete("/leads/{lead_id}")
def delete_lead(lead_id: int, current_user: dict = Depends(get_current_user)):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Delete related floor pricing first
            try:
                cursor.execute("DELETE FROM inventory_floor_pricing WHERE lead_id = %s", (lead_id,))
            except Exception as e:
                logging.warning(f"Could not delete floor pricing: {e}")
            
            # Delete related actions/followups
            try:
                cursor.execute("DELETE FROM actions WHERE lead_id = %s", (lead_id,))
            except Exception as e:
                logging.warning(f"Could not delete actions: {e}")
            
            # Delete the lead
            cursor.execute("DELETE FROM leads WHERE id = %s", (lead_id,))
            affected = cursor.rowcount
            conn.commit()
            
            if affected == 0:
                raise HTTPException(status_code=404, detail="Lead not found")
        
        return {"message": "Lead deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting lead {lead_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete lead: {str(e)}")

# ============= Builder Routes =============
@api_router.get("/builders", response_model=List[BuilderResponse])
def get_builders(
    skip: int = 0,
    limit: int = 500,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM builders ORDER BY builder_name ASC LIMIT %s OFFSET %s",
            (limit, skip)
        )
        builders = cursor.fetchall()
    
    return [BuilderResponse(**builder) for builder in builders]

@api_router.get("/builders/{builder_id}", response_model=BuilderResponse)
def get_builder(builder_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM builders WHERE id = %s", (builder_id,))
        builder = cursor.fetchone()
        
    if not builder:
        raise HTTPException(status_code=404, detail="Builder not found")
    
    return BuilderResponse(**builder)

@api_router.get("/builders/{builder_id}/leads")
def get_builder_leads(builder_id: int, current_user: dict = Depends(get_current_user)):
    """Get all leads associated with a builder"""
    with get_db() as conn:
        cursor = conn.cursor()
        # Get leads where builder_id matches or lead_type is 'builder' and name matches builder
        cursor.execute("""
            SELECT l.*, u.full_name as created_by_name 
            FROM leads l
            LEFT JOIN users u ON l.created_by = u.id
            WHERE l.builder_id = %s 
            AND (l.is_deleted IS NULL OR l.is_deleted = 0)
            ORDER BY l.created_at DESC
        """, (builder_id,))
        leads = cursor.fetchall()
        
        # Fetch floor pricing for leads
        if leads:
            lead_ids = [lead['id'] for lead in leads]
            placeholders = ','.join(['%s'] * len(lead_ids))
            cursor.execute(
                f"SELECT * FROM inventory_floor_pricing WHERE lead_id IN ({placeholders}) ORDER BY lead_id, id",
                lead_ids
            )
            all_floor_pricing = cursor.fetchall()
            
            floor_pricing_map = {}
            for fp in all_floor_pricing:
                lead_id = fp['lead_id']
                if lead_id not in floor_pricing_map:
                    floor_pricing_map[lead_id] = []
                floor_pricing_map[lead_id].append({
                    'floor_label': fp['floor_label'],
                    'floor_amount': float(fp['floor_amount']) if fp['floor_amount'] else 0
                })
            
            for lead in leads:
                lead['floor_pricing'] = floor_pricing_map.get(lead['id'], [])
    
    return leads

@api_router.post("/builders", response_model=BuilderResponse)
def create_builder(builder: BuilderCreate, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO builders (builder_name, company_name, phone, address, created_at)
               VALUES (%s, %s, %s, %s, %s)""",
            (builder.builder_name, builder.company_name, builder.phone, builder.address, datetime.utcnow())
        )
        conn.commit()
        builder_id = cursor.lastrowid
        
        cursor.execute("SELECT * FROM builders WHERE id = %s", (builder_id,))
        created = cursor.fetchone()
    
    return BuilderResponse(**created)

@api_router.put("/builders/{builder_id}", response_model=BuilderResponse)
def update_builder(builder_id: int, builder: BuilderCreate, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE builders SET builder_name=%s, company_name=%s, phone=%s, address=%s
               WHERE id=%s""",
            (builder.builder_name, builder.company_name, builder.phone, builder.address, builder_id)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Builder not found")
        
        cursor.execute("SELECT * FROM builders WHERE id = %s", (builder_id,))
        updated = cursor.fetchone()
    
    return BuilderResponse(**updated)

@api_router.delete("/builders/{builder_id}")
def delete_builder(builder_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM builders WHERE id = %s", (builder_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Builder not found")
    
    return {"message": "Builder deleted successfully"}

# ============= Followup/Conversation Routes =============
class FollowupCreate(BaseModel):
    lead_id: int
    channel: str  # Call, WhatsApp, SMS, Email, Visit
    outcome: str  # Connected, No Answer, Call Back, Left VM, etc.
    notes: Optional[str] = None
    followup_date: Optional[str] = None  # Date of this conversation
    next_followup: Optional[str] = None  # Next followup datetime

class FollowupResponse(BaseModel):
    id: int
    lead_id: Optional[int]
    owner_id: Optional[int]
    channel: Optional[str]
    outcome: Optional[str]
    notes: Optional[str]
    followup_date: Optional[date]
    next_followup: Optional[datetime]
    created_at: datetime
    owner_name: Optional[str] = None
    
    class Config:
        from_attributes = True

@api_router.get("/leads/{lead_id}/followups")
def get_lead_followups(lead_id: int, current_user: dict = Depends(get_current_user)):
    """Get all followups/conversations for a lead"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.*, u.full_name as owner_name 
            FROM followups f
            LEFT JOIN users u ON f.owner_id = u.id
            WHERE f.lead_id = %s AND (f.is_deleted IS NULL OR f.is_deleted = 0)
            ORDER BY f.created_at DESC
        """, (lead_id,))
        followups = cursor.fetchall()
    
    return followups

@api_router.post("/leads/{lead_id}/followups")
def create_followup(lead_id: int, followup: FollowupCreate, current_user: dict = Depends(get_current_user)):
    """Log a new conversation/followup for a lead"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Parse dates
        followup_date = None
        if followup.followup_date:
            try:
                followup_date = datetime.strptime(followup.followup_date, '%Y-%m-%d').date()
            except:
                followup_date = datetime.now().date()
        else:
            followup_date = datetime.now().date()
            
        next_followup = None
        if followup.next_followup:
            try:
                next_followup = datetime.strptime(followup.next_followup, '%Y-%m-%dT%H:%M')
            except:
                pass
        
        cursor.execute("""
            INSERT INTO followups (lead_id, owner_id, channel, outcome, notes, followup_date, next_followup, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (lead_id, current_user['id'], followup.channel, followup.outcome, 
              followup.notes, followup_date, next_followup, datetime.now()))
        conn.commit()
        
        followup_id = cursor.lastrowid
        cursor.execute("""
            SELECT f.*, u.full_name as owner_name 
            FROM followups f
            LEFT JOIN users u ON f.owner_id = u.id
            WHERE f.id = %s
        """, (followup_id,))
        created = cursor.fetchone()
    
    return created

# ============= Reminder Routes (using actions table) =============
@api_router.get("/reminders")
def get_reminders(
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get all actions/reminders with lead information"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT a.*, l.name as lead_name, l.phone as lead_phone, l.created_by as lead_created_by
               FROM actions a
               LEFT JOIN leads l ON a.lead_id = l.id
               WHERE a.user_id = %s
               ORDER BY a.due_date ASC, a.due_time ASC LIMIT %s OFFSET %s""",
            (current_user['id'], limit, skip)
        )
        actions = cursor.fetchall()
        
        # Convert to expected frontend format
        result = []
        for a in actions:
            a_dict = dict(a)
            # Map actions columns to reminder format for frontend
            # Combine due_date and due_time into reminder_date
            if a_dict.get('due_date'):
                date_str = str(a_dict['due_date'])
                time_str = str(a_dict.get('due_time', '00:00:00') or '00:00:00')
                a_dict['reminder_date'] = f"{date_str}T{time_str}"
            
            # Map action_type to reminder_type
            a_dict['reminder_type'] = a_dict.get('action_type', 'Task')
            
            # Map description to notes
            a_dict['notes'] = a_dict.get('description')
            
            result.append(a_dict)
    
    # Apply masking to phone numbers based on user permissions
    user_role = current_user.get('role', '')
    user_id = current_user.get('id')
    for item in result:
        lead_created_by = item.get('lead_created_by')
        if should_mask_data(user_role, user_id, lead_created_by):
            if item.get('lead_phone'):
                item['lead_phone'] = mask_phone(item['lead_phone'])
    
    return result

@api_router.post("/reminders")
def create_reminder(reminder: ReminderCreate, current_user: dict = Depends(get_current_user)):
    """Create a new action/reminder in the actions table"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Parse the reminder_date to extract date and time parts (IST)
        # Format expected: YYYY-MM-DDTHH:MM:SS (already in IST from frontend)
        reminder_datetime = reminder.reminder_date
        if isinstance(reminder_datetime, str) and 'T' in reminder_datetime:
            parts = reminder_datetime.split('T')
            date_part = parts[0]  # YYYY-MM-DD
            time_part = parts[1] if len(parts) > 1 else '00:00:00'  # HH:MM:SS
            # Ensure time format is correct
            if len(time_part) == 5:  # HH:MM
                time_part += ':00'
        else:
            date_part = str(reminder_datetime)[:10] if reminder_datetime else None
            time_part = '00:00:00'
        
        # Map status to valid enum values for actions table
        # actions status: 'Pending','Completed','Snoozed','Missed','Dismissed','Up Coming'
        status = reminder.status
        if status.lower() == 'pending':
            status = 'Pending'
        elif status.lower() == 'completed':
            status = 'Completed'
        
        # Insert into actions table
        cursor.execute(
            """INSERT INTO actions (user_id, lead_id, title, description, action_type, due_date, due_time, status, priority, is_notified)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (current_user['id'], reminder.lead_id, reminder.title, reminder.notes,
             reminder.reminder_type, date_part, time_part, status, reminder.priority or 'Medium', 0)
        )
        conn.commit()
        action_id = cursor.lastrowid
        
        cursor.execute(
            """SELECT a.*, l.name as lead_name, l.phone as lead_phone 
               FROM actions a
               LEFT JOIN leads l ON a.lead_id = l.id
               WHERE a.id = %s""", 
            (action_id,)
        )
        created = cursor.fetchone()
        
        # Format response for frontend
        if created:
            created = dict(created)
            if created.get('due_date'):
                date_str = str(created['due_date'])
                time_str = str(created.get('due_time', '00:00:00') or '00:00:00')
                created['reminder_date'] = f"{date_str}T{time_str}"
            created['reminder_type'] = created.get('action_type', 'Task')
            created['notes'] = created.get('description')
    
    return created

@api_router.put("/reminders/{reminder_id}")
def update_reminder(reminder_id: int, reminder_data: dict, current_user: dict = Depends(get_current_user)):
    """Update an action/reminder"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Handle reminder_date - split into due_date and due_time parts
        if 'reminder_date' in reminder_data:
            reminder_datetime = reminder_data['reminder_date']
            if isinstance(reminder_datetime, str) and 'T' in reminder_datetime:
                parts = reminder_datetime.split('T')
                reminder_data['due_date'] = parts[0]
                time_part = parts[1] if len(parts) > 1 else '00:00:00'
                if len(time_part) == 5:
                    time_part += ':00'
                reminder_data['due_time'] = time_part
            del reminder_data['reminder_date']
        
        # Map reminder_type to action_type
        if 'reminder_type' in reminder_data:
            reminder_data['action_type'] = reminder_data['reminder_type']
            del reminder_data['reminder_type']
        
        # Map notes to description
        if 'notes' in reminder_data:
            reminder_data['description'] = reminder_data['notes']
            del reminder_data['notes']
        
        # Map status
        if 'status' in reminder_data:
            status = reminder_data['status']
            if status.lower() == 'pending':
                reminder_data['status'] = 'Pending'
            elif status.lower() == 'completed':
                reminder_data['status'] = 'Completed'
                reminder_data['completed_at'] = datetime.now()
        
        # Build dynamic update query
        update_fields = []
        values = []
        
        allowed_fields = ['title', 'due_date', 'due_time', 'action_type', 'description', 'status', 'lead_id', 'priority', 'outcome', 'completed_at', 'is_notified']
        
        for field in allowed_fields:
            if field in reminder_data:
                update_fields.append(f"{field} = %s")
                values.append(reminder_data[field])
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        values.append(reminder_id)
        values.append(current_user['id'])
        query = f"UPDATE actions SET {', '.join(update_fields)} WHERE id = %s AND user_id = %s"
        
        cursor.execute(query, values)
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Action/Reminder not found")
        
        cursor.execute(
            """SELECT a.*, l.name as lead_name, l.phone as lead_phone 
               FROM actions a
               LEFT JOIN leads l ON a.lead_id = l.id
               WHERE a.id = %s""", 
            (reminder_id,)
        )
        updated = cursor.fetchone()
        
        # Format response
        if updated:
            updated = dict(updated)
            if updated.get('due_date'):
                date_str = str(updated['due_date'])
                time_str = str(updated.get('due_time', '00:00:00') or '00:00:00')
                updated['reminder_date'] = f"{date_str}T{time_str}"
            updated['reminder_type'] = updated.get('action_type', 'Task')
            updated['notes'] = updated.get('description')
    
    return updated

@api_router.delete("/reminders/{reminder_id}")
def delete_reminder(reminder_id: int, current_user: dict = Depends(get_current_user)):
    """Delete an action/reminder"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM actions WHERE id = %s AND user_id = %s", (reminder_id, current_user['id']))
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Action/Reminder not found")
    
    return {"message": "Action/Reminder deleted successfully"}

# ============= Dashboard Routes =============
@api_router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Total leads (exclude deleted)
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE (is_deleted IS NULL OR is_deleted = 0)")
        total_leads = cursor.fetchone()['count']
        
        # Client leads (buyer, tenant) - exclude deleted
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_type IN ('buyer', 'tenant') AND (is_deleted IS NULL OR is_deleted = 0)")
        client_leads = cursor.fetchone()['count']
        
        # Inventory leads (seller, landlord, builder) - exclude deleted
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_type IN ('seller', 'landlord', 'builder') AND (is_deleted IS NULL OR is_deleted = 0)")
        inventory_leads = cursor.fetchone()['count']
        
        # Temperature counts - exclude deleted
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_temperature = 'Hot' AND (is_deleted IS NULL OR is_deleted = 0)")
        hot_leads = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_temperature = 'Warm' AND (is_deleted IS NULL OR is_deleted = 0)")
        warm_leads = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_temperature = 'Cold' AND (is_deleted IS NULL OR is_deleted = 0)")
        cold_leads = cursor.fetchone()['count']
        
        # Builders
        cursor.execute("SELECT COUNT(*) as count FROM builders")
        total_builders = cursor.fetchone()['count']
        
        # Today's reminders from actions table
        today = datetime.utcnow().date()
        cursor.execute("SELECT COUNT(*) as count FROM actions WHERE DATE(due_date) = %s AND status IN ('Pending', 'Up Coming')", (today,))
        today_reminders = cursor.fetchone()['count']
        
        # Pending reminders - all pending actions
        cursor.execute("SELECT COUNT(*) as count FROM actions WHERE status = 'Pending'")
        pending_reminders = cursor.fetchone()['count']
        
        # ===== Enhanced Stats =====
        
        # Missed follow-ups (past due date with Pending status)
        cursor.execute("""
            SELECT COUNT(*) as count FROM actions 
            WHERE (due_date < CURDATE() OR (due_date = CURDATE() AND due_time < CURTIME()))
            AND status = 'Pending'
        """)
        missed_followups = cursor.fetchone()['count']
        
        # Upcoming follow-ups (today and next 3 days)
        cursor.execute("""
            SELECT COUNT(*) as count FROM actions 
            WHERE due_date >= CURDATE() AND due_date <= DATE_ADD(CURDATE(), INTERVAL 3 DAY)
            AND status IN ('Pending', 'Up Coming')
        """)
        upcoming_followups = cursor.fetchone()['count']
        
        # Leads added this week
        week_start = today - timedelta(days=today.weekday())
        cursor.execute("""
            SELECT COUNT(*) as count FROM leads 
            WHERE DATE(created_at) >= %s AND (is_deleted IS NULL OR is_deleted = 0)
        """, (week_start,))
        leads_this_week = cursor.fetchone()['count']
        
        # Follow-ups completed this week (use due_date since updated_at might not exist)
        cursor.execute("""
            SELECT COUNT(*) as count FROM actions 
            WHERE DATE(due_date) >= %s AND status = 'Completed'
        """, (week_start,))
        followups_completed_this_week = cursor.fetchone()['count']
        
        # Leads converted this week (status is Won, use created_at since updated_at might not exist)
        cursor.execute("""
            SELECT COUNT(*) as count FROM leads 
            WHERE lead_status = 'Won' AND (is_deleted IS NULL OR is_deleted = 0)
        """)
        leads_converted_this_week = cursor.fetchone()['count']
        
        # Lead funnel stats (for client leads only)
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_status = 'New' AND lead_type IN ('buyer', 'tenant') AND (is_deleted IS NULL OR is_deleted = 0)")
        new_leads = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_status = 'Contacted' AND lead_type IN ('buyer', 'tenant') AND (is_deleted IS NULL OR is_deleted = 0)")
        contacted_leads = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_status = 'Qualified' AND lead_type IN ('buyer', 'tenant') AND (is_deleted IS NULL OR is_deleted = 0)")
        qualified_leads = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_status = 'Negotiating' AND lead_type IN ('buyer', 'tenant') AND (is_deleted IS NULL OR is_deleted = 0)")
        negotiating_leads = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_status = 'Won' AND lead_type IN ('buyer', 'tenant') AND (is_deleted IS NULL OR is_deleted = 0)")
        won_leads = cursor.fetchone()['count']

        # Leads created but not yet touched by an action/reminder.
        try:
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM leads l
                WHERE l.lead_status = 'New'
                AND (l.is_deleted IS NULL OR l.is_deleted = 0)
                AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.lead_id = l.id)
            """)
            uncontacted_new_leads = cursor.fetchone()['count']
        except Exception:
            uncontacted_new_leads = 0

        # Site visits scheduled for today.
        try:
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM site_visits
                WHERE DATE(visit_date) = CURDATE()
                AND (status IS NULL OR status NOT IN ('Cancelled', 'Canceled'))
            """)
            today_site_visits = cursor.fetchone()['count']
        except Exception:
            today_site_visits = 0

        # Active leads with no recent follow-up activity.
        try:
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM leads l
                LEFT JOIN (
                    SELECT lead_id, MAX(due_date) as last_action_date
                    FROM actions
                    GROUP BY lead_id
                ) latest_action ON latest_action.lead_id = l.id
                WHERE (l.is_deleted IS NULL OR l.is_deleted = 0)
                AND (l.lead_status IS NULL OR l.lead_status NOT IN ('Won', 'Closed/Lost', 'Lost', 'Sold', 'Already Rented'))
                AND COALESCE(DATE(latest_action.last_action_date), DATE(l.created_at)) < DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            """)
            stale_leads = cursor.fetchone()['count']
        except Exception:
            stale_leads = 0

        # Inventory still available for matching.
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM leads
            WHERE lead_type IN ('seller', 'landlord', 'builder')
            AND (is_deleted IS NULL OR is_deleted = 0)
            AND (lead_status IS NULL OR lead_status NOT IN ('Won', 'Closed/Lost', 'Lost', 'Sold', 'Already Rented'))
        """)
        available_inventory = cursor.fetchone()['count']
    
    return DashboardStats(
        total_leads=total_leads,
        client_leads=client_leads,
        inventory_leads=inventory_leads,
        hot_leads=hot_leads,
        warm_leads=warm_leads,
        cold_leads=cold_leads,
        total_builders=total_builders,
        today_reminders=today_reminders,
        pending_reminders=pending_reminders,
        missed_followups=missed_followups,
        upcoming_followups=upcoming_followups,
        leads_this_week=leads_this_week,
        followups_completed_this_week=followups_completed_this_week,
        leads_converted_this_week=leads_converted_this_week,
        new_leads=new_leads,
        contacted_leads=contacted_leads,
        qualified_leads=qualified_leads,
        negotiating_leads=negotiating_leads,
        won_leads=won_leads,
        uncontacted_new_leads=uncontacted_new_leads,
        today_site_visits=today_site_visits,
        stale_leads=stale_leads,
        available_inventory=available_inventory
    )

# ============= AI Features Routes =============

# Initialize LLM key
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY')

@api_router.get("/ai/smart-matches", response_model=List[AIMatchResult])
def get_smart_matches(current_user: dict = Depends(get_current_user), limit: int = 5):
    """Get AI-powered smart matches between buyers and inventory"""
    matches = []
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get active buyers with preferences
        cursor.execute("""
            SELECT id, name, location, budget_min, budget_max, floor, bhk, building_facing, property_type
            FROM leads 
            WHERE lead_type IN ('buyer', 'tenant') 
            AND lead_status NOT IN ('Won', 'Closed/Lost', 'Lost')
            AND (is_deleted IS NULL OR is_deleted = 0)
            ORDER BY RAND()
            LIMIT 20
        """)
        buyers = cursor.fetchall()
        
        # Get available inventory
        cursor.execute("""
            SELECT id, name, location, budget_min, budget_max, floor, bhk, building_facing, property_type, area_size
            FROM leads 
            WHERE lead_type IN ('seller', 'landlord', 'builder') 
            AND lead_status NOT IN ('Sold', 'Closed/Lost', 'Lost')
            AND (is_deleted IS NULL OR is_deleted = 0)
            LIMIT 100
        """)
        inventory = cursor.fetchall()
        
        # Simple matching algorithm
        for buyer in buyers:
            buyer_locations = set((buyer.get('location') or '').lower().split(','))
            buyer_locations = {loc.strip() for loc in buyer_locations if loc.strip()}
            buyer_budget_min = float(buyer.get('budget_min') or 0)
            buyer_budget_max = float(buyer.get('budget_max') or 999999)
            buyer_floors = set((buyer.get('floor') or '').lower().split(','))
            buyer_floors = {f.strip() for f in buyer_floors if f.strip()}
            
            for inv in inventory:
                score = 0
                reasons = []
                
                # Location match
                inv_location = (inv.get('location') or '').lower().strip()
                if inv_location and any(loc in inv_location or inv_location in loc for loc in buyer_locations if loc):
                    score += 40
                    reasons.append(f"Location match: {inv.get('location')}")
                
                # Budget match
                inv_budget = float(inv.get('budget_min') or inv.get('budget_max') or 0)
                if inv_budget > 0:
                    if buyer_budget_min <= inv_budget <= buyer_budget_max:
                        score += 30
                        reasons.append(f"Budget in range")
                    elif buyer_budget_min * 0.8 <= inv_budget <= buyer_budget_max * 1.2:
                        score += 15
                        reasons.append(f"Budget close to range")
                
                # Floor match
                inv_floors = set((inv.get('floor') or '').lower().split(','))
                inv_floors = {f.strip() for f in inv_floors if f.strip()}
                if buyer_floors and inv_floors and buyer_floors.intersection(inv_floors):
                    score += 20
                    reasons.append(f"Floor preference match")
                
                # BHK match
                if buyer.get('bhk') and inv.get('bhk') and buyer.get('bhk') == inv.get('bhk'):
                    score += 10
                    reasons.append(f"BHK match: {inv.get('bhk')}")
                
                if score >= 40 and reasons:
                    matches.append({
                        'buyer_id': buyer['id'],
                        'buyer_name': buyer['name'],
                        'inventory_id': inv['id'],
                        'inventory_name': inv['name'] or f"Inventory #{inv['id']}",
                        'location': inv.get('location') or 'N/A',
                        'match_score': min(score, 100),
                        'match_reasons': reasons
                    })
        
        # Sort by score and return top matches
        matches.sort(key=lambda x: x['match_score'], reverse=True)
        return matches[:limit]

@api_router.get("/ai/urgent-followups")
def get_urgent_followups(current_user: dict = Depends(get_current_user), limit: int = 10):
    """Get urgent follow-ups (missed + today's)"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get missed and today's follow-ups
        cursor.execute("""
            SELECT a.id, a.lead_id, a.title, a.due_date, a.due_time, a.status,
                   l.name as lead_name, l.phone as lead_phone, l.lead_type, l.created_by
            FROM actions a
            JOIN leads l ON a.lead_id = l.id
            WHERE a.status IN ('Pending', 'Up Coming')
            AND (a.due_date < CURDATE() OR a.due_date = CURDATE())
            AND (l.is_deleted IS NULL OR l.is_deleted = 0)
            ORDER BY a.due_date ASC, a.due_time ASC
            LIMIT %s
        """, (limit,))
        
        followups = cursor.fetchall()
        
        result = []
        today = datetime.utcnow().date()
        
        for f in followups:
            due_date = f['due_date']
            is_missed = due_date < today if due_date else False
            
            result.append({
                'id': f['id'],
                'lead_id': f['lead_id'],
                'lead_name': f['lead_name'],
                'lead_phone': f['lead_phone'],
                'lead_type': f['lead_type'],
                'title': f['title'],
                'due_date': str(due_date) if due_date else None,
                'due_time': str(f['due_time']) if f['due_time'] else None,
                'status': 'Missed' if is_missed else 'Due Today',
                'is_missed': is_missed,
                'created_by': f['created_by']
            })
        
        # Apply masking to phone numbers based on user permissions
        user_role = current_user.get('role', '')
        user_id = current_user.get('id')
        for item in result:
            created_by = item.get('created_by')
            if should_mask_data(user_role, user_id, created_by):
                if item.get('lead_phone'):
                    item['lead_phone'] = mask_phone(item['lead_phone'])
        
        return result

@api_router.post("/ai/generate-message", response_model=AIMessageResponse)
async def generate_ai_message(request: AIMessageRequest, current_user: dict = Depends(get_current_user)):
    """Generate AI-powered follow-up message for WhatsApp"""
    
    if not EMERGENT_LLM_KEY or LlmChat is None or UserMessage is None:
        raise HTTPException(status_code=500, detail="AI features not configured")
    
    # Get lead details
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT l.*, a.title as last_action_title, a.due_date as last_action_date
            FROM leads l
            LEFT JOIN actions a ON l.id = a.lead_id AND a.status = 'Pending'
            WHERE l.id = %s
            ORDER BY a.due_date DESC
            LIMIT 1
        """, (request.lead_id,))
        lead = cursor.fetchone()
        
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
    
    # Build context for AI
    lead_name = lead.get('name', 'Customer')
    lead_type = lead.get('lead_type', 'buyer')
    location = lead.get('location', '')
    budget_min = lead.get('budget_min', 0)
    budget_max = lead.get('budget_max', 0)
    property_type = lead.get('property_type', '')
    bhk = lead.get('bhk', '')
    
    message_templates = {
        'first_contact': f"Generate a warm, professional WhatsApp message for first contact with a {lead_type} named {lead_name}. They are interested in {bhk or 'a property'} in {location or 'the area'}. Budget range: {budget_min}-{budget_max} Cr. Keep it brief and friendly.",
        'follow_up': f"Generate a professional follow-up WhatsApp message for {lead_name} who is a {lead_type}. They showed interest in {property_type or 'property'} in {location}. Remind them about our discussion and ask about their decision. Keep it brief.",
        'negotiation': f"Generate a negotiation-focused WhatsApp message for {lead_name}. They are interested in {bhk} {property_type or 'property'} in {location} with budget {budget_min}-{budget_max} Cr. Mention flexibility and value. Keep it professional.",
        'closing': f"Generate a closing WhatsApp message for {lead_name} to finalize the deal. They are a {lead_type} interested in {location}. Create urgency while being professional. Keep it brief."
    }
    
    prompt = message_templates.get(request.message_type, message_templates['follow_up'])
    if request.custom_context:
        prompt += f" Additional context: {request.custom_context}"
    
    prompt += " Respond ONLY with the message text, no explanations. Use Hindi-English mix for natural conversation. Keep it under 100 words."
    
    try:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"message-gen-{request.lead_id}",
            system_message="You are a helpful real estate assistant who generates professional WhatsApp messages. Keep messages brief, friendly, and professional. Use natural Hindi-English mix."
        ).with_model("openai", "gpt-5.2")
        
        user_message = UserMessage(text=prompt)
        response = await chat.send_message(user_message)
        
        return AIMessageResponse(
            message=response.strip(),
            lead_name=lead_name,
            message_type=request.message_type
        )
    except Exception as e:
        logging.error(f"AI message generation error: {e}")
        # Fallback to template messages
        fallback_messages = {
            'first_contact': f"Hi {lead_name}, This is from Sagar Home. I understand you're looking for a property in {location}. I have some excellent options that match your requirements. Would you like to discuss? 🏠",
            'follow_up': f"Hi {lead_name}, Hope you're doing well! Just wanted to follow up on our earlier conversation about properties in {location}. Any updates from your side? Let me know if you need more details. 😊",
            'negotiation': f"Hi {lead_name}, I've spoken with the owner and there's some flexibility on the pricing for the {location} property. This is a great opportunity. Shall we discuss further? 📞",
            'closing': f"Hi {lead_name}, Great news! Everything is set for the {location} property. Let's finalize the paperwork soon to secure this deal for you. When can we meet? 🎉"
        }
        return AIMessageResponse(
            message=fallback_messages.get(request.message_type, fallback_messages['follow_up']),
            lead_name=lead_name,
            message_type=request.message_type
        )

# ============= Inventory File Upload Routes =============
MAX_IMAGES = 12
MAX_PDFS = 4
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif']
ALLOWED_PDF_TYPES = ['application/pdf']

# File upload directory - stored on server
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", ROOT_DIR / "uploads" / "inventory"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Base URL for accessing files
UPLOAD_BASE_URL = "/api/uploads/inventory"

@api_router.post("/inventory/{lead_id}/files")
async def upload_inventory_file(
    lead_id: int,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Upload an image or PDF file for an inventory"""
    # Validate file type
    content_type = file.content_type or ''
    
    if content_type in ALLOWED_IMAGE_TYPES:
        file_type = 'image'
    elif content_type in ALLOWED_PDF_TYPES:
        file_type = 'pdf'
    else:
        raise HTTPException(status_code=400, detail=f"File type not allowed. Allowed: images (JPEG, PNG, GIF, WebP, HEIC) and PDF")
    
    # Read file content
    file_content = await file.read()
    file_size = len(file_content)
    
    # Validate file size
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File too large. Maximum size: 10MB")
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if lead exists
        cursor.execute("SELECT id, lead_type FROM leads WHERE id = %s", (lead_id,))
        lead = cursor.fetchone()
        if not lead:
            raise HTTPException(status_code=404, detail="Inventory not found")
        
        # Count existing files
        cursor.execute(
            "SELECT file_type, COUNT(*) as count FROM inventory_files WHERE lead_id = %s AND is_deleted = 0 GROUP BY file_type",
            (lead_id,)
        )
        file_counts = {row['file_type']: row['count'] for row in cursor.fetchall()}
        
        image_count = file_counts.get('image', 0)
        pdf_count = file_counts.get('pdf', 0)
        
        if file_type == 'image' and image_count >= MAX_IMAGES:
            raise HTTPException(status_code=400, detail=f"Maximum {MAX_IMAGES} images allowed per inventory")
        
        if file_type == 'pdf' and pdf_count >= MAX_PDFS:
            raise HTTPException(status_code=400, detail=f"Maximum {MAX_PDFS} PDF files allowed per inventory")
        
        # Generate unique filename
        import uuid
        file_ext = Path(file.filename).suffix or ('.jpg' if file_type == 'image' else '.pdf')
        unique_filename = f"{lead_id}_{uuid.uuid4().hex}{file_ext}"
        
        # Create lead-specific directory
        lead_dir = UPLOAD_DIR / str(lead_id)
        lead_dir.mkdir(parents=True, exist_ok=True)
        
        # Save file to disk
        file_path = lead_dir / unique_filename
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        # Generate file URL
        file_url = f"{UPLOAD_BASE_URL}/{lead_id}/{unique_filename}"
        
        # Insert file record
        cursor.execute(
            """INSERT INTO inventory_files (lead_id, file_name, file_type, content_type, file_size, file_path, file_url, uploaded_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (lead_id, file.filename, file_type, content_type, file_size, str(file_path), file_url, current_user['id'])
        )
        conn.commit()
        file_id = cursor.lastrowid
        
    return {
        "id": file_id,
        "lead_id": lead_id,
        "file_name": file.filename,
        "file_type": file_type,
        "content_type": content_type,
        "file_size": file_size,
        "file_url": file_url,
        "message": "File uploaded successfully"
    }

@api_router.get("/inventory/{lead_id}/files")
def get_inventory_files(lead_id: int, current_user: dict = Depends(get_current_user)):
    """Get list of files for an inventory"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, lead_id, file_name, file_type, content_type, file_size, file_url, created_at
               FROM inventory_files
               WHERE lead_id = %s AND is_deleted = 0
               ORDER BY file_type, created_at DESC""",
            (lead_id,)
        )
        files = cursor.fetchall()
        
        # Format the response
        result = []
        for f in files:
            result.append({
                'id': f['id'],
                'lead_id': f['lead_id'],
                'file_name': f['file_name'],
                'file_type': f['file_type'],
                'content_type': f['content_type'],
                'file_size': f['file_size'],
                'file_url': f['file_url'],
                'created_at': f['created_at'].isoformat() if f['created_at'] else None
            })
        
    return result

@api_router.get("/uploads/inventory/{lead_id}/{filename}")
def serve_inventory_file(lead_id: int, filename: str):
    """Serve uploaded file"""
    file_path = UPLOAD_DIR / str(lead_id) / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    # Determine content type
    import mimetypes
    content_type, _ = mimetypes.guess_type(str(file_path))
    if not content_type:
        content_type = 'application/octet-stream'
    
    with open(file_path, 'rb') as f:
        content = f.read()
    
    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Content-Disposition": f"inline; filename={filename}",
            "Cache-Control": "public, max-age=86400"
        }
    )

@api_router.delete("/inventory/files/{file_id}")
def delete_inventory_file(file_id: int, current_user: dict = Depends(get_current_user)):
    """Soft delete a file"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get file path before deleting
        cursor.execute("SELECT file_path FROM inventory_files WHERE id = %s", (file_id,))
        file_record = cursor.fetchone()
        
        cursor.execute(
            "UPDATE inventory_files SET is_deleted = 1 WHERE id = %s",
            (file_id,)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="File not found")
        
        # Optionally delete file from disk
        if file_record and file_record['file_path']:
            try:
                file_path = Path(file_record['file_path'])
                if file_path.exists():
                    file_path.unlink()
            except:
                pass  # Ignore file deletion errors
    
    return {"message": "File deleted successfully"}

@api_router.get("/inventory/{lead_id}/files/count")
def get_inventory_files_count(lead_id: int, current_user: dict = Depends(get_current_user)):
    """Get count of files for an inventory"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT file_type, COUNT(*) as count 
               FROM inventory_files 
               WHERE lead_id = %s AND is_deleted = 0 
               GROUP BY file_type""",
            (lead_id,)
        )
        counts = {row['file_type']: row['count'] for row in cursor.fetchall()}
        
    return {
        'images': counts.get('image', 0),
        'pdfs': counts.get('pdf', 0),
        'total': counts.get('image', 0) + counts.get('pdf', 0),
        'max_images': MAX_IMAGES,
        'max_pdfs': MAX_PDFS
    }

# ============= Tentative Pricing Routes =============
class PlotPricingCreate(BaseModel):
    location_id: int
    circle: str
    plot_size: int
    price_per_sq_yard: str
    min_price: float
    max_price: float
    tentative_price: Optional[float] = None
    floors: List[dict] = []  # [{floor_label: str, tentative_floor_price: str}]

@api_router.get("/pricing")
def get_all_pricing(current_user: dict = Depends(get_current_user)):
    """Get all tentative pricing grouped by location"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get all plot pricing with location info
        cursor.execute("""
            SELECT pp.*, l.name as location_name, l.colony_category, l.`Circle Rate` as location_circle_rate
            FROM plot_pricing pp
            JOIN locations l ON pp.location_id = l.id
            ORDER BY l.name ASC, pp.plot_size ASC
        """)
        plot_pricings = cursor.fetchall()
        
        # Get all floor pricing
        cursor.execute("""
            SELECT pf.* FROM plot_floor_pricing pf
            ORDER BY pf.plot_pricing_id ASC
        """)
        floor_pricings = cursor.fetchall()
        
        # Group floor pricing by plot_pricing_id
        floors_by_plot = {}
        for fp in floor_pricings:
            plot_id = fp['plot_pricing_id']
            if plot_id not in floors_by_plot:
                floors_by_plot[plot_id] = []
            floors_by_plot[plot_id].append({
                'id': fp['id'],
                'floor_label': fp['floor_label'],
                'tentative_floor_price': fp['tentative_floor_price']
            })
        
        # Group by location
        grouped = {}
        for pp in plot_pricings:
            loc_name = pp['location_name']
            if loc_name not in grouped:
                grouped[loc_name] = {
                    'location_id': pp['location_id'],
                    'location_name': loc_name,
                    'colony_category': pp['colony_category'],
                    'circle_rate': pp['location_circle_rate'] or pp['circle'],
                    'plots': []
                }
            
            grouped[loc_name]['plots'].append({
                'id': pp['id'],
                'plot_size': pp['plot_size'],
                'price_per_sq_yard': pp['price_per_sq_yard'],
                'min_price': float(pp['min_price']) if pp['min_price'] else 0,
                'max_price': float(pp['max_price']) if pp['max_price'] else 0,
                'tentative_price': float(pp['tentative_price']) if pp['tentative_price'] else None,
                'floors': floors_by_plot.get(pp['id'], [])
            })
        
        return list(grouped.values())

@api_router.get("/pricing/{pricing_id}")
def get_pricing_detail(pricing_id: int, current_user: dict = Depends(get_current_user)):
    """Get details for a specific plot pricing"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT pp.*, l.name as location_name, l.colony_category, l.`Circle Rate` as location_circle_rate
            FROM plot_pricing pp
            JOIN locations l ON pp.location_id = l.id
            WHERE pp.id = %s
        """, (pricing_id,))
        pricing = cursor.fetchone()
        
        if not pricing:
            raise HTTPException(status_code=404, detail="Pricing not found")
        
        # Get floor pricing
        cursor.execute("""
            SELECT * FROM plot_floor_pricing WHERE plot_pricing_id = %s
        """, (pricing_id,))
        floors = cursor.fetchall()
        
        result = dict(pricing)
        result['floors'] = [dict(f) for f in floors]
        return result

@api_router.post("/pricing")
def create_pricing(pricing: PlotPricingCreate, current_user: dict = Depends(get_current_user)):
    """Create new plot pricing with floor prices"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Insert plot pricing
        cursor.execute("""
            INSERT INTO plot_pricing (location_id, circle, plot_size, price_per_sq_yard, min_price, max_price, tentative_price, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
        """, (pricing.location_id, pricing.circle, pricing.plot_size, pricing.price_per_sq_yard, 
              pricing.min_price, pricing.max_price, pricing.tentative_price))
        conn.commit()
        
        plot_pricing_id = cursor.lastrowid
        
        # Insert floor pricing
        for floor in pricing.floors:
            if floor.get('floor_label') and floor.get('tentative_floor_price'):
                cursor.execute("""
                    INSERT INTO plot_floor_pricing (plot_pricing_id, floor_label, tentative_floor_price, created_at, updated_at)
                    VALUES (%s, %s, %s, NOW(), NOW())
                """, (plot_pricing_id, floor['floor_label'], floor['tentative_floor_price']))
        
        conn.commit()
        
        return {"id": plot_pricing_id, "message": "Pricing created successfully"}

@api_router.put("/pricing/{pricing_id}")
def update_pricing(pricing_id: int, pricing_data: dict, current_user: dict = Depends(get_current_user)):
    """Update plot pricing"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Update plot pricing
        update_fields = []
        values = []
        allowed_fields = ['location_id', 'circle', 'plot_size', 'price_per_sq_yard', 'min_price', 'max_price', 'tentative_price']
        
        for field in allowed_fields:
            if field in pricing_data:
                update_fields.append(f"{field} = %s")
                values.append(pricing_data[field])
        
        if update_fields:
            update_fields.append("updated_at = NOW()")
            values.append(pricing_id)
            query = f"UPDATE plot_pricing SET {', '.join(update_fields)} WHERE id = %s"
            cursor.execute(query, values)
        
        # Update floor pricing if provided
        if 'floors' in pricing_data:
            # Delete existing floors
            cursor.execute("DELETE FROM plot_floor_pricing WHERE plot_pricing_id = %s", (pricing_id,))
            
            # Insert new floors
            for floor in pricing_data['floors']:
                if floor.get('floor_label') and floor.get('tentative_floor_price'):
                    cursor.execute("""
                        INSERT INTO plot_floor_pricing (plot_pricing_id, floor_label, tentative_floor_price, created_at, updated_at)
                        VALUES (%s, %s, %s, NOW(), NOW())
                    """, (pricing_id, floor['floor_label'], floor['tentative_floor_price']))
        
        conn.commit()
        
        return {"message": "Pricing updated successfully"}

@api_router.delete("/pricing/{pricing_id}")
def delete_pricing(pricing_id: int, current_user: dict = Depends(get_current_user)):
    """Delete plot pricing and its floor prices"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Delete floor pricing first
        cursor.execute("DELETE FROM plot_floor_pricing WHERE plot_pricing_id = %s", (pricing_id,))
        
        # Delete plot pricing
        cursor.execute("DELETE FROM plot_pricing WHERE id = %s", (pricing_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Pricing not found")
        
        return {"message": "Pricing deleted successfully"}

@api_router.get("/locations/all")
def get_all_locations(current_user: dict = Depends(get_current_user)):
    """Get all locations with circle rates"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, colony_category, `Circle Rate` as circle_rate
            FROM locations
            ORDER BY name ASC
        """)
        locations = cursor.fetchall()
        return [dict(l) for l in locations]

# ============= Site Visit Scheduler =============

class SiteVisitCreate(BaseModel):
    lead_id: Optional[int] = None
    property_lead_id: Optional[int] = None  # The inventory/property to visit
    visit_date: Optional[str] = None
    visit_time: Optional[str] = None
    location: Optional[str] = None
    visit_type: Optional[str] = "Property Visit"
    meeting_point: Optional[str] = None
    location_url: Optional[str] = None
    visit_order: Optional[int] = None
    client_feedback: Optional[str] = None
    outcome: Optional[str] = None
    interest_level: Optional[str] = None
    objections: Optional[str] = None
    quoted_price: Optional[float] = None
    next_followup_date: Optional[str] = None
    next_followup_time: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = "Scheduled"  # Scheduled, Completed, Cancelled, Rescheduled

class SiteVisitResponse(BaseModel):
    id: int
    lead_id: int
    property_lead_id: Optional[int]
    visit_date: str
    visit_time: Optional[str]
    location: Optional[str]
    notes: Optional[str]
    status: str
    visit_type: Optional[str]
    meeting_point: Optional[str]
    location_url: Optional[str]
    visit_order: Optional[int]
    client_feedback: Optional[str]
    outcome: Optional[str]
    interest_level: Optional[str]
    objections: Optional[str]
    quoted_price: Optional[float]
    next_followup_date: Optional[str]
    next_followup_time: Optional[str]
    lead_name: Optional[str]
    property_name: Optional[str]
    created_by: Optional[int]
    created_at: Optional[str]

def ensure_site_visits_table(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS site_visits (
            id INT AUTO_INCREMENT PRIMARY KEY,
            lead_id INT,
            property_lead_id INT,
            visit_date DATE,
            visit_time TIME,
            location VARCHAR(255),
            notes TEXT,
            status VARCHAR(50) DEFAULT 'Scheduled',
            created_by INT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    optional_columns = [
        ("visit_type", "VARCHAR(100) DEFAULT 'Property Visit'"),
        ("meeting_point", "VARCHAR(255) NULL"),
        ("location_url", "TEXT NULL"),
        ("visit_order", "INT NULL"),
        ("client_feedback", "TEXT NULL"),
        ("outcome", "VARCHAR(100) NULL"),
        ("interest_level", "VARCHAR(50) NULL"),
        ("objections", "TEXT NULL"),
        ("quoted_price", "DECIMAL(15,2) NULL"),
        ("next_followup_date", "DATE NULL"),
        ("next_followup_time", "TIME NULL"),
        ("updated_at", "DATETIME NULL"),
    ]
    for column, definition in optional_columns:
        try:
            cursor.execute(f"ALTER TABLE site_visits ADD COLUMN {column} {definition}")
        except Exception:
            pass

@api_router.get("/site-visits")
def get_site_visits(current_user: dict = Depends(get_current_user), status: Optional[str] = None):
    """Get all site visits"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            ensure_site_visits_table(cursor)
            conn.commit()
            
            query = """
                SELECT sv.*, 
                       l.name as lead_name, l.phone as lead_phone, l.created_by as lead_created_by,
                       p.name as property_name, p.location as property_location,
                       p.Property_locationUrl as property_map_url,
                       COALESCE(sv.location_url, p.Property_locationUrl) as location_url
                FROM site_visits sv
                LEFT JOIN leads l ON sv.lead_id = l.id
                LEFT JOIN leads p ON sv.property_lead_id = p.id
                WHERE sv.created_by = %s
            """
            params = [current_user['id']]
            
            if status:
                query += " AND sv.status = %s"
                params.append(status)
            
            query += " ORDER BY sv.visit_date ASC, sv.visit_time ASC, COALESCE(sv.visit_order, 999) ASC"
            cursor.execute(query, params)
            visits = cursor.fetchall()
            return [dict(v) for v in visits]
    except Exception as e:
        logging.error(f"Site visits error: {e}")
        return []

@api_router.post("/site-visits")
def create_site_visit(visit: SiteVisitCreate, current_user: dict = Depends(get_current_user)):
    """Create a new site visit"""
    if not visit.lead_id or not visit.visit_date:
        raise HTTPException(status_code=400, detail="Lead and visit date are required")

    with get_db() as conn:
        cursor = conn.cursor()
        ensure_site_visits_table(cursor)
        cursor.execute("""
            INSERT INTO site_visits (
                lead_id, property_lead_id, visit_date, visit_time, location, visit_type,
                meeting_point, location_url, visit_order, client_feedback, outcome, interest_level,
                objections, quoted_price, next_followup_date, next_followup_time,
                notes, status, created_by, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            visit.lead_id, visit.property_lead_id, visit.visit_date, visit.visit_time,
            visit.location, visit.visit_type or 'Property Visit', visit.meeting_point,
            visit.location_url, visit.visit_order, visit.client_feedback, visit.outcome, visit.interest_level,
            visit.objections, visit.quoted_price, visit.next_followup_date, visit.next_followup_time,
            visit.notes, visit.status or 'Scheduled', current_user['id']
        ))
        conn.commit()
        return {"id": cursor.lastrowid, "message": "Site visit scheduled successfully"}

@api_router.put("/site-visits/{visit_id}")
def update_site_visit(visit_id: int, visit: SiteVisitCreate, current_user: dict = Depends(get_current_user)):
    """Update a site visit"""
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_site_visits_table(cursor)
        update_data = visit.dict(exclude_unset=True)
        if not update_data:
            raise HTTPException(status_code=400, detail="No fields to update")

        allowed_fields = [
            'lead_id', 'property_lead_id', 'visit_date', 'visit_time', 'location',
            'visit_type', 'meeting_point', 'location_url', 'visit_order', 'client_feedback',
            'outcome', 'interest_level', 'objections', 'quoted_price',
            'next_followup_date', 'next_followup_time', 'notes', 'status'
        ]
        set_parts = []
        values = []
        for field in allowed_fields:
            if field in update_data:
                set_parts.append(f"{field}=%s")
                values.append(update_data[field])

        set_parts.append("updated_at=NOW()")
        values.extend([visit_id, current_user['id']])
        cursor.execute(
            f"UPDATE site_visits SET {', '.join(set_parts)} WHERE id=%s AND created_by=%s",
            values
        )
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Site visit not found")
        return {"message": "Site visit updated successfully"}

@api_router.delete("/site-visits/{visit_id}")
def delete_site_visit(visit_id: int, current_user: dict = Depends(get_current_user)):
    """Delete a site visit"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM site_visits WHERE id=%s AND created_by=%s", (visit_id, current_user['id']))
        conn.commit()
        return {"message": "Site visit deleted successfully"}

# ============= Deal/Transaction Tracker =============

class DealCreate(BaseModel):
    lead_id: int
    property_lead_id: Optional[int] = None
    deal_amount: Optional[float] = None
    commission_percent: Optional[float] = None
    commission_amount: Optional[float] = None
    status: Optional[str] = "Negotiation"  # Negotiation, Agreement, Documentation, Payment, Closed, Cancelled
    payment_received: Optional[float] = 0
    notes: Optional[str] = None
    expected_closing_date: Optional[str] = None

@api_router.get("/deals")
def get_deals(current_user: dict = Depends(get_current_user), status: Optional[str] = None):
    """Get all deals"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            # First check if table exists, create if not
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS deals (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    lead_id INT,
                    property_lead_id INT,
                    deal_amount DECIMAL(15,2),
                    commission_percent DECIMAL(5,2),
                    commission_amount DECIMAL(15,2),
                    status VARCHAR(50) DEFAULT 'Negotiation',
                    payment_received DECIMAL(15,2) DEFAULT 0,
                    notes TEXT,
                    expected_closing_date DATE,
                    created_by INT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            
            # Try to add missing columns if table already existed
            try:
                cursor.execute("ALTER TABLE deals ADD COLUMN property_lead_id INT")
                conn.commit()
            except:
                pass  # Column already exists
            
            # Check if property_lead_id column exists
            cursor.execute("SHOW COLUMNS FROM deals LIKE 'property_lead_id'")
            has_property_lead_id = cursor.fetchone() is not None
            
            if has_property_lead_id:
                query = """
                    SELECT d.*, 
                           l.name as lead_name, l.phone as lead_phone,
                           p.name as property_name, p.location as property_location
                    FROM deals d
                    LEFT JOIN leads l ON d.lead_id = l.id
                    LEFT JOIN leads p ON d.property_lead_id = p.id
                    WHERE 1=1
                """
            else:
                query = """
                    SELECT d.*, 
                           l.name as lead_name, l.phone as lead_phone,
                           NULL as property_name, NULL as property_location
                    FROM deals d
                    LEFT JOIN leads l ON d.lead_id = l.id
                    WHERE 1=1
                """
            params = []
            
            if current_user['role'] != 'admin':
                query += " AND d.created_by = %s"
                params.append(current_user['id'])
            
            if status:
                query += " AND d.status = %s"
                params.append(status)
            
            query += " ORDER BY d.created_at DESC"
            cursor.execute(query, params)
            deals = cursor.fetchall()
            return [dict(d) for d in deals]
    except Exception as e:
        logging.error(f"Deals error: {e}")
        return []

@api_router.post("/deals")
def create_deal(deal: DealCreate, current_user: dict = Depends(get_current_user)):
    """Create a new deal"""
    with get_db() as conn:
        cursor = conn.cursor()
        commission = deal.commission_amount or (deal.deal_amount * deal.commission_percent / 100 if deal.deal_amount and deal.commission_percent else 0)
        cursor.execute("""
            INSERT INTO deals (lead_id, property_lead_id, deal_amount, commission_percent, commission_amount, 
            status, payment_received, notes, expected_closing_date, created_by, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (deal.lead_id, deal.property_lead_id, deal.deal_amount, deal.commission_percent, commission,
              deal.status or 'Negotiation', deal.payment_received or 0, deal.notes, deal.expected_closing_date, current_user['id']))
        conn.commit()
        return {"id": cursor.lastrowid, "message": "Deal created successfully"}

@api_router.put("/deals/{deal_id}")
def update_deal(deal_id: int, deal: DealCreate, current_user: dict = Depends(get_current_user)):
    """Update a deal"""
    with get_db() as conn:
        cursor = conn.cursor()
        commission = deal.commission_amount or (deal.deal_amount * deal.commission_percent / 100 if deal.deal_amount and deal.commission_percent else 0)
        cursor.execute("""
            UPDATE deals SET lead_id=%s, property_lead_id=%s, deal_amount=%s, commission_percent=%s, 
            commission_amount=%s, status=%s, payment_received=%s, notes=%s, expected_closing_date=%s
            WHERE id=%s
        """, (deal.lead_id, deal.property_lead_id, deal.deal_amount, deal.commission_percent, commission,
              deal.status, deal.payment_received, deal.notes, deal.expected_closing_date, deal_id))
        conn.commit()
        return {"message": "Deal updated successfully"}

@api_router.delete("/deals/{deal_id}")
def delete_deal(deal_id: int, current_user: dict = Depends(get_current_user)):
    """Delete a deal"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM deals WHERE id=%s", (deal_id,))
        conn.commit()
        return {"message": "Deal deleted successfully"}

# ============= Activity Log / Timeline =============

@api_router.get("/leads/{lead_id}/activity")
def get_lead_activity(lead_id: int, current_user: dict = Depends(get_current_user)):
    """Get activity timeline for a lead"""
    activities = []
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get follow-ups/actions
        cursor.execute("""
            SELECT 'followup' as type, id, title as description, due_date as activity_date, 
                   status, created_at, NULL as created_by_name
            FROM actions WHERE lead_id = %s
            ORDER BY created_at DESC
        """, (lead_id,))
        followups = cursor.fetchall()
        for f in followups:
            activities.append({
                'type': 'followup',
                'id': f['id'],
                'description': f['description'],
                'date': str(f['activity_date']) if f['activity_date'] else str(f['created_at']),
                'status': f['status'],
                'icon': 'calendar'
            })
        
        # Get site visits
        cursor.execute("""
            SELECT 'visit' as type, id, CONCAT('Site Visit: ', COALESCE(location, 'Property')) as description,
                   visit_date as activity_date, status, created_at
            FROM site_visits WHERE lead_id = %s
            ORDER BY created_at DESC
        """, (lead_id,))
        visits = cursor.fetchall()
        for v in visits:
            activities.append({
                'type': 'visit',
                'id': v['id'],
                'description': v['description'],
                'date': str(v['activity_date']) if v['activity_date'] else str(v['created_at']),
                'status': v['status'],
                'icon': 'location'
            })
        
        # Get deals
        cursor.execute("""
            SELECT 'deal' as type, id, CONCAT('Deal: ₹', COALESCE(deal_amount, 0), ' Cr') as description,
                   expected_closing_date as activity_date, status, created_at
            FROM deals WHERE lead_id = %s
            ORDER BY created_at DESC
        """, (lead_id,))
        deals = cursor.fetchall()
        for d in deals:
            activities.append({
                'type': 'deal',
                'id': d['id'],
                'description': d['description'],
                'date': str(d['activity_date']) if d['activity_date'] else str(d['created_at']),
                'status': d['status'],
                'icon': 'cash'
            })
    
    # Sort by date descending
    activities.sort(key=lambda x: x['date'] if x['date'] else '', reverse=True)
    return activities

# ============= Team Management =============

@api_router.get("/activity-logs")
def get_activity_logs(current_user: dict = Depends(get_current_user), limit: int = 50):
    """Get recent activity logs across all leads"""
    activities = []
    
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Get recent follow-ups/actions with lead names
            cursor.execute("""
                SELECT a.id, a.lead_id, a.title, a.action_type, a.description, a.status, 
                       a.created_at, l.name as lead_name, u.full_name as created_by
                FROM actions a
                LEFT JOIN leads l ON a.lead_id = l.id
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.created_at DESC
                LIMIT %s
            """, (limit,))
            actions = cursor.fetchall()
            
            for a in actions:
                activities.append({
                    'id': a['id'],
                    'lead_id': a['lead_id'],
                    'lead_name': a['lead_name'] or f"Lead #{a['lead_id']}" if a['lead_id'] else 'Unknown',
                    'action_type': a['action_type'] or 'Task',
                    'description': a['title'] or a['description'] or 'Activity',
                    'created_by': a['created_by'] or 'System',
                    'created_at': a['created_at'].isoformat() if a['created_at'] else None
                })
            
            # Get recent site visits (wrapped in try-catch)
            try:
                cursor.execute("""
                    SELECT sv.id, sv.lead_id, sv.location, sv.status, sv.visit_date, sv.created_at,
                           l.name as lead_name, u.full_name as created_by
                    FROM site_visits sv
                    LEFT JOIN leads l ON sv.lead_id = l.id
                    LEFT JOIN users u ON sv.created_by = u.id
                    ORDER BY sv.created_at DESC
                    LIMIT %s
                """, (limit // 2,))
                visits = cursor.fetchall()
                
                for v in visits:
                    activities.append({
                        'id': v['id'] + 10000,
                        'lead_id': v['lead_id'],
                        'lead_name': v['lead_name'] or f"Lead #{v['lead_id']}" if v['lead_id'] else 'Unknown',
                        'action_type': 'visit',
                        'description': f"Site visit at {v['location'] or 'property'} - {v['status']}",
                        'created_by': v['created_by'] or 'System',
                        'created_at': v['created_at'].isoformat() if v['created_at'] else (v['visit_date'].isoformat() if v.get('visit_date') else None)
                    })
            except Exception as e:
                logging.warning(f"Could not fetch site visits for activity log: {e}")
            
            # Get recent deals (wrapped in try-catch, with flexible column handling)
            try:
                cursor.execute("""
                    SELECT d.id, d.lead_id, d.created_at,
                           l.name as lead_name
                    FROM deals d
                    LEFT JOIN leads l ON d.lead_id = l.id
                    ORDER BY d.created_at DESC
                    LIMIT %s
                """, (limit // 2,))
                deals = cursor.fetchall()
                
                for d in deals:
                    activities.append({
                        'id': d['id'] + 20000,
                        'lead_id': d['lead_id'],
                        'lead_name': d['lead_name'] or f"Lead #{d['lead_id']}" if d['lead_id'] else 'Unknown',
                        'action_type': 'deal',
                        'description': "Deal created",
                        'created_by': 'System',
                        'created_at': d['created_at'].isoformat() if d['created_at'] else None
                    })
            except Exception as e:
                logging.warning(f"Could not fetch deals for activity log: {e}")
        
        # Sort all activities by created_at descending
        activities.sort(key=lambda x: x['created_at'] or '', reverse=True)
        return activities[:limit]
    except Exception as e:
        logging.error(f"Activity logs error: {e}")
        return []

@api_router.get("/team/members")
def get_team_members(current_user: dict = Depends(get_current_user)):
    """Get all team members (admin only)"""
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, full_name, email, role, created_at,
                   (SELECT COUNT(*) FROM leads WHERE created_by = users.id) as lead_count
            FROM users ORDER BY full_name
        """)
        members = cursor.fetchall()
        return [dict(m) for m in members]

@api_router.post("/team/assign-lead")
def assign_lead_to_member(lead_id: int, user_id: int, current_user: dict = Depends(get_current_user)):
    """Assign a lead to a team member"""
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE leads SET assigned_to = %s WHERE id = %s", (user_id, lead_id))
        conn.commit()
        return {"message": "Lead assigned successfully"}

@api_router.get("/team/performance")
def get_team_performance(current_user: dict = Depends(get_current_user)):
    """Get team performance stats"""
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.full_name, u.username,
                   COUNT(DISTINCT l.id) as total_leads,
                   SUM(CASE WHEN l.lead_status = 'Won' THEN 1 ELSE 0 END) as won_deals,
                   COUNT(DISTINCT sv.id) as site_visits,
                   COUNT(DISTINCT a.id) as followups_done
            FROM users u
            LEFT JOIN leads l ON l.created_by = u.id
            LEFT JOIN site_visits sv ON sv.created_by = u.id
            LEFT JOIN actions a ON a.user_id = u.id AND a.status = 'Completed'
            GROUP BY u.id, u.full_name, u.username
            ORDER BY total_leads DESC
        """)
        performance = cursor.fetchall()
        return [dict(p) for p in performance]

# ============= User Permissions =============

@api_router.get("/user/permissions")
def get_user_permissions(current_user: dict = Depends(get_current_user)):
    """Get current user's permissions"""
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_user_permission_columns(cursor)
        conn.commit()
        
        # Admins always have export permission
        if current_user['role'] == 'admin':
            return {"can_export": True, "is_admin": True}
        
        # Check user's specific permission
        cursor.execute("SELECT can_export FROM users WHERE id = %s", (current_user['id'],))
        result = cursor.fetchone()
        can_export = result['can_export'] if result and 'can_export' in result else False
        
        return {"can_export": bool(can_export), "is_admin": False}

@api_router.put("/user/{user_id}/permissions")
def update_user_permissions(user_id: int, can_export: bool, current_user: dict = Depends(get_current_user)):
    """Update user permissions (admin only)"""
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_user_permission_columns(cursor)
        
        cursor.execute("UPDATE users SET can_export = %s WHERE id = %s", (1 if can_export else 0, user_id))
        log_security_event(cursor, current_user['id'], "permission_update", "user", user_id, {"can_export": can_export})
        conn.commit()
        return {"message": "Permissions updated successfully"}

@api_router.get("/team/members-with-permissions")
def get_team_members_with_permissions(current_user: dict = Depends(get_current_user)):
    """Get all team members with their permissions (admin only)"""
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_user_permission_columns(cursor)
        conn.commit()
        
        cursor.execute("""
            SELECT id, username, full_name, email, role, can_export,
                   (SELECT COUNT(*) FROM leads WHERE created_by = users.id) as lead_count
            FROM users ORDER BY full_name
        """)
        members = cursor.fetchall()
        result = []
        for m in members:
            member_dict = dict(m)
            member_dict['can_export'] = bool(member_dict.get('can_export', 0))
            result.append(member_dict)
        return result

@api_router.get("/security/audit-logs")
def get_security_audit_logs(limit: int = 100, current_user: dict = Depends(get_current_user)):
    """Get recent security audit events (admin only)"""
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")

    safe_limit = max(1, min(limit, 500))
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_security_audit_table(cursor)
        cursor.execute("""
            SELECT a.*, u.username, u.full_name
            FROM security_audit_logs a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.created_at DESC
            LIMIT %s
        """, (safe_limit,))
        logs = cursor.fetchall()
        return [dict(item) for item in logs]

# ============= Bulk Import/Export =============

@api_router.post("/leads/bulk-import")
async def bulk_import_leads(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Import leads from CSV file"""
    import csv
    import io
    
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")
    
    content = await file.read()
    decoded = content.decode('utf-8')
    reader = csv.DictReader(io.StringIO(decoded))
    
    imported = 0
    errors = []
    
    with get_db() as conn:
        cursor = conn.cursor()
        for row in reader:
            try:
                cursor.execute("""
                    INSERT INTO leads (name, phone, email, lead_type, location, budget_min, budget_max, 
                    property_type, bhk, lead_temperature, lead_status, notes, created_by, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, (
                    row.get('name', ''),
                    row.get('phone', ''),
                    row.get('email', ''),
                    row.get('lead_type', 'buyer'),
                    row.get('location', ''),
                    float(row.get('budget_min', 0)) if row.get('budget_min') else None,
                    float(row.get('budget_max', 0)) if row.get('budget_max') else None,
                    row.get('property_type', ''),
                    row.get('bhk', ''),
                    row.get('lead_temperature', 'Hot'),
                    row.get('lead_status', 'New'),
                    row.get('notes', ''),
                    current_user['id']
                ))
                imported += 1
            except Exception as e:
                errors.append(f"Row {imported + 1}: {str(e)}")
        conn.commit()
    
    return {"imported": imported, "errors": errors}

@api_router.get("/leads/export")
def export_leads(
    lead_type: Optional[str] = None,
    category: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Export leads to CSV format"""
    with get_db() as conn:
        cursor = conn.cursor()
        if not user_can_export(cursor, current_user):
            log_security_event(cursor, current_user['id'], "export_denied", "leads", None, {
                "lead_type": lead_type,
                "category": category
            })
            conn.commit()
            raise HTTPException(status_code=403, detail="Export permission required")

        query = "SELECT * FROM leads WHERE (is_deleted IS NULL OR is_deleted = 0)"
        params = []

        selected_category = (category or '').lower()
        if selected_category == "clients":
            query += " AND LOWER(IFNULL(lead_type, '')) IN ('buyer', 'tenant')"
        elif selected_category == "inventory":
            query += " AND LOWER(IFNULL(lead_type, '')) IN ('seller', 'landlord', 'builder', 'owner')"
        elif lead_type:
            query += " AND lead_type = %s"
            params.append(lead_type)

        query += " ORDER BY created_at DESC"
        cursor.execute(query, params)
        leads = cursor.fetchall()
        log_security_event(cursor, current_user['id'], "leads_exported", "leads", None, {
            "lead_type": lead_type,
            "category": selected_category or "all",
            "row_count": len(leads)
        })
        conn.commit()

        columns = [
            "id", "name", "phone", "email", "lead_type", "lead_status", "temperature",
            "budget_min", "budget_max", "unit", "location", "address", "property_type",
            "area_size", "floor", "bhk", "source", "created_by", "created_at", "updated_at"
        ]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for lead in leads:
            writer.writerow({column: lead.get(column, "") for column in columns})

        file_category = selected_category or lead_type or "all"
        filename = f"leads_{file_category}_{datetime.now().strftime('%Y-%m-%d')}.csv"
        return Response(
            content="\ufeff" + output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

# ============= Property Gallery =============

@api_router.get("/leads/{lead_id}/gallery")
def get_property_gallery(lead_id: int, current_user: dict = Depends(get_current_user)):
    """Get all images for a property"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, lead_id, file_name, file_path, file_type, file_size, uploaded_at
            FROM inventory_files WHERE lead_id = %s AND file_type LIKE 'image/%'
            ORDER BY uploaded_at DESC
        """, (lead_id,))
        images = cursor.fetchall()
        return [dict(img) for img in images]

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
