from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, File, UploadFile, Form, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pathlib import Path
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
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

def should_mask_data(
    user_role: str,
    user_id: int,
    created_by: Optional[int],
    assigned_to: Optional[int] = None,
) -> bool:
    """Mask unless the user is admin, creator, or current assignee."""
    # Admin can see everything
    if user_role and user_role.lower() == 'admin':
        return False
    # Creator and current assignee can see sensitive lead data.
    if created_by is not None and int(user_id or 0) == int(created_by):
        return False
    if assigned_to is not None and int(user_id or 0) == int(assigned_to):
        return False
    # Everyone else gets masked data
    return True

def apply_lead_masking(lead: dict, user_role: str, user_id: int) -> dict:
    """Apply masking to a lead based on user permissions"""
    created_by = lead.get('created_by')
    assigned_to = (
        lead.get('current_assignee_id')
        or lead.get('assigned_to')
        or lead.get('assigned_user_id')
    )
    can_view_sensitive = not should_mask_data(user_role, user_id, created_by, assigned_to)
    lead['can_view_sensitive'] = can_view_sensitive
    if not can_view_sensitive:
        if lead.get('phone'):
            lead['phone'] = mask_phone(lead['phone'])
        if lead.get('address'):
            lead['address'] = mask_address(lead['address'])
        if 'Property_locationUrl' in lead:
            lead['Property_locationUrl'] = None
        if 'property_location_url' in lead:
            lead['property_location_url'] = None
        if 'location_url' in lead:
            lead['location_url'] = None
    return lead

def current_assignee_map(cursor, lead_ids: List[int]) -> Dict[int, Optional[int]]:
    """Resolve the current owner from web assignments, falling back to leads.assigned_to."""
    clean_ids = sorted({int(item) for item in lead_ids if int(item) > 0})
    if not clean_ids:
        return {}
    placeholders = ','.join(['%s'] * len(clean_ids))
    result: Dict[int, Optional[int]] = {}
    if _table_exists(cursor, 'lead_assignments'):
        assignment_columns = _table_columns(cursor, 'lead_assignments')
        assignment_order = "assigned_at DESC"
        if 'id' in assignment_columns:
            assignment_order += ", id DESC"
        cursor.execute(f"""
            SELECT lead_id, user_id
            FROM lead_assignments
            WHERE lead_id IN ({placeholders})
            ORDER BY lead_id, {assignment_order}
        """, clean_ids)
        for row in cursor.fetchall():
            result.setdefault(int(row['lead_id']), row.get('user_id'))
    if 'assigned_to' in _table_columns(cursor, 'leads'):
        cursor.execute(f"""
            SELECT id, assigned_to
            FROM leads
            WHERE id IN ({placeholders})
        """, clean_ids)
        for row in cursor.fetchall():
            result.setdefault(int(row['id']), row.get('assigned_to'))
    return result

def attach_current_assignees(cursor, leads: List[dict]) -> List[dict]:
    assignment_map = current_assignee_map(cursor, [lead.get('id') for lead in leads if lead.get('id')])
    for lead in leads:
        lead['current_assignee_id'] = assignment_map.get(int(lead['id'])) if lead.get('id') else None
    return leads

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

APP_FEATURE_FLAGS = {
    "buyer_leads": "Clients",
    "seller_inventory": "Inventory",
    "builders_agents": "Builders",
    "followups": "Reminders",
    "daily_workbench": "Workbench",
    "legacy_inventory": "Legacy Inventory",
    "assigned_leads": "Assigned Leads",
    "team_inbox": "Team Inbox",
    "agent_performance": "Performance",
    "site_visits": "Site Visits",
    "activity_feed": "Activity",
    "lead_map": "Lead Map",
    "inventory_pricing": "Pricing",
    "data_export": "Export",
    "team_management": "Team",
}

def ensure_user_mobile_feature_flags_table(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_mobile_feature_flags (
            user_id INT NOT NULL,
            feature_key VARCHAR(80) NOT NULL,
            is_enabled TINYINT(1) NOT NULL DEFAULT 1,
            updated_by INT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, feature_key),
            KEY idx_user_mobile_feature_flags_feature (feature_key),
            KEY idx_user_mobile_feature_flags_enabled (user_id, is_enabled)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    # Preserve existing app choices the first time the separate mobile scope is used.
    try:
        cursor.execute(
            """
            INSERT IGNORE INTO user_mobile_feature_flags
                (user_id, feature_key, is_enabled, updated_by, created_at, updated_at)
            SELECT user_id, feature_key, is_enabled, updated_by, created_at, updated_at
            FROM user_feature_flags
            WHERE feature_key IN ({})
               OR feature_key = '__default__'
            """.format(",".join(["%s"] * len(APP_FEATURE_FLAGS))),
            tuple(APP_FEATURE_FLAGS.keys()),
        )
    except Exception as exc:
        logging.warning(f"Existing feature flag migration to mobile scope skipped: {exc}")

def get_user_mobile_feature_flag_values(cursor, user_id: int) -> Dict[str, bool]:
    cursor.execute(
        """
        SELECT feature_key, is_enabled
        FROM user_mobile_feature_flags
        WHERE user_id = %s
          AND (feature_key IN ({}) OR feature_key = '__default__')
        """.format(",".join(["%s"] * len(APP_FEATURE_FLAGS))),
        tuple([user_id] + list(APP_FEATURE_FLAGS.keys())),
    )
    stored = {row["feature_key"]: bool(row["is_enabled"]) for row in cursor.fetchall()}
    default_enabled = stored.get("__default__", True)
    return {
        key: stored.get(key, default_enabled)
        for key in APP_FEATURE_FLAGS
    }

def ensure_action_assignment_column(cursor):
    try:
        cursor.execute("ALTER TABLE actions ADD COLUMN assigned_to INT NULL")
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

def ensure_collaboration_tables(cursor):
    """Keep mobile collaboration compatible with the shared web LMS schema."""
    try:
        cursor.execute("SHOW COLUMNS FROM leads LIKE 'assigned_to'")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE leads ADD COLUMN assigned_to INT NULL")
    except Exception as exc:
        logging.warning(f"Lead assignment bridge column guard skipped: {exc}")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lead_assignments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            lead_id INT NOT NULL,
            user_id INT NOT NULL,
            assigned_by INT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_lead_user (lead_id, user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lead_comments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            lead_id INT NOT NULL,
            user_id INT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_lead_comments_lead_created (lead_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lead_comment_mentions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            comment_id INT NOT NULL,
            user_id INT NOT NULL,
            is_read TINYINT(1) NOT NULL DEFAULT 0,
            read_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_comment_mention (comment_id, user_id),
            INDEX idx_mentions_user_read (user_id, is_read)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lead_collaborators (
            lead_id INT NOT NULL,
            user_id INT NOT NULL,
            added_by INT NULL,
            source VARCHAR(40) NOT NULL DEFAULT 'mention',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (lead_id, user_id),
            INDEX idx_lead_collaborators_user (user_id, lead_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lead_handoffs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            lead_id INT NOT NULL,
            from_user_id INT NULL,
            to_user_id INT NOT NULL,
            initiated_by INT NOT NULL,
            note TEXT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            responded_at DATETIME NULL,
            INDEX idx_handoff_lead_status (lead_id, status),
            INDEX idx_handoff_recipient_status (to_user_id, status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collaboration_notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            lead_id INT NULL,
            notification_type VARCHAR(40) NOT NULL,
            reference_id INT NULL,
            message VARCHAR(500) NOT NULL,
            is_read TINYINT(1) NOT NULL DEFAULT 0,
            read_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_collaboration_user_read (user_id, is_read, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

def can_access_collaboration_lead(cursor, lead_id: int, current_user: dict) -> bool:
    role = str(current_user.get('role') or '').strip().lower()
    if role in {'admin', 'manager'}:
        return True
    cursor.execute("""
        SELECT l.id
        FROM leads l
        WHERE l.id = %s AND (l.is_deleted IS NULL OR l.is_deleted = 0)
          AND (
              l.created_by = %s
              OR l.assigned_to = %s
              OR EXISTS (
                  SELECT 1 FROM lead_assignments la
                  WHERE la.lead_id = l.id AND la.user_id = %s
              )
              OR EXISTS (
                  SELECT 1 FROM lead_collaborators lc
                  WHERE lc.lead_id = l.id AND lc.user_id = %s
              )
              OR EXISTS (
                  SELECT 1 FROM lead_handoffs lh
                  WHERE lh.lead_id = l.id AND lh.to_user_id = %s AND lh.status = 'pending'
              )
          )
        LIMIT 1
    """, (
        lead_id,
        current_user['id'],
        current_user['id'],
        current_user['id'],
        current_user['id'],
        current_user['id'],
    ))
    return bool(cursor.fetchone())

INVENTORY_LEAD_TYPES_SQL = "'seller', 'landlord', 'builder', 'agent'"
CLIENT_LEAD_TYPES_SQL = "'buyer', 'tenant'"

def ensure_whatsapp_tracking_columns(cursor):
    required = {
        'last_message_sent_on': "ALTER TABLE leads ADD COLUMN last_message_sent_on DATETIME NULL",
        'last_sent_message': "ALTER TABLE leads ADD COLUMN last_sent_message TEXT NULL",
        'whatsapp_sent_flag': "ALTER TABLE leads ADD COLUMN whatsapp_sent_flag TINYINT(1) NOT NULL DEFAULT 0",
    }
    for column, alter_sql in required.items():
        try:
            cursor.execute("SHOW COLUMNS FROM leads LIKE %s", (column,))
            if not cursor.fetchone():
                cursor.execute(alter_sql)
        except Exception as exc:
            logging.warning(f"WhatsApp lead column guard skipped for {column}: {exc}")

def ensure_whatsapp_logs_table(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whatsapp_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            lead_id INT NULL,
            phone VARCHAR(50) NULL,
            message TEXT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'opened',
            source VARCHAR(50) NULL,
            created_by INT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_whatsapp_logs_lead_id (lead_id),
            INDEX idx_whatsapp_logs_created_at (created_at),
            INDEX idx_whatsapp_logs_phone (phone)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    optional_columns = {
        'phone': "ALTER TABLE whatsapp_logs ADD COLUMN phone VARCHAR(50) NULL",
        'message': "ALTER TABLE whatsapp_logs ADD COLUMN message TEXT NULL",
        'source': "ALTER TABLE whatsapp_logs ADD COLUMN source VARCHAR(50) NULL",
        'created_by': "ALTER TABLE whatsapp_logs ADD COLUMN created_by INT NULL",
        'created_at': "ALTER TABLE whatsapp_logs ADD COLUMN created_at DATETIME NULL",
    }
    for column, alter_sql in optional_columns.items():
        try:
            cursor.execute("SHOW COLUMNS FROM whatsapp_logs LIKE %s", (column,))
            if not cursor.fetchone():
                cursor.execute(alter_sql)
        except Exception as exc:
            logging.warning(f"WhatsApp log column guard skipped for {column}: {exc}")

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
    property_age: Optional[str] = None
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
    assigned_to: Optional[int] = None
    status: str = "Pending"
    priority: Optional[str] = "Medium"

class CollaborationCommentCreate(BaseModel):
    body: str
    mention_ids: Optional[List[int]] = None

class CollaborationHandoffCreate(BaseModel):
    to_user_id: int
    note: Optional[str] = None

class CollaborationHandoffResponse(BaseModel):
    decision: str

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
    buyer_type: Optional[str] = None
    buyer_phone: Optional[str] = None
    buyer_status: Optional[str] = None
    buyer_temperature: Optional[str] = None
    buyer_budget_min: Optional[float] = None
    buyer_budget_max: Optional[float] = None
    inventory_id: int
    inventory_name: str
    inventory_type: Optional[str] = None
    inventory_phone: Optional[str] = None
    inventory_status: Optional[str] = None
    inventory_price_min: Optional[float] = None
    inventory_price_max: Optional[float] = None
    inventory_floor: Optional[str] = None
    inventory_bhk: Optional[str] = None
    inventory_area_size: Optional[str] = None
    location: str
    match_score: int
    match_reasons: List[str]
    is_saved: bool = False
    is_hot: bool = False
    updated_on: Optional[str] = None

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

class WhatsAppMessageCreate(BaseModel):
    phone: str
    message: str
    lead_id: Optional[str] = None
    status: Optional[str] = "opened"
    source: Optional[str] = "ios_app"

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
def _coerce_valid_date(value: Any) -> Optional[date]:
    """Return a real calendar date, treating legacy zero/invalid dates as missing."""
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value

    value_text = str(value).strip()
    if not value_text or value_text.startswith('0000-00-00'):
        return None
    try:
        return datetime.strptime(value_text[:10], '%Y-%m-%d').date()
    except (TypeError, ValueError):
        logger.warning("Ignoring invalid lead date while calculating score: %r", value)
        return None


def _coerce_float(value: Any) -> float:
    """Convert legacy numeric values without allowing one bad row to abort a list."""
    if value is None or value == '':
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        logger.warning("Ignoring invalid lead number while calculating score: %r", value)
        return 0.0


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
    valid_followup_date = _coerce_valid_date(last_followup_date)
    if valid_followup_date:
        days_since_contact = max(0, (today - valid_followup_date).days)
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
        created_date = _coerce_valid_date(lead.get('created_at'))
        if created_date:
            days_since_created = max(0, (today - created_date).days)
            if days_since_created <= 3:
                score += 15
                breakdown.append(('Recency', 15, f'New lead ({days_since_created}d old)'))
            else:
                breakdown.append(('Recency', 0, 'Never contacted'))
        else:
            breakdown.append(('Recency', 0, 'Never contacted'))
    
    # 3. Budget Score (0-20 points)
    budget_max = _coerce_float(lead.get('budget_max') or lead.get('budget_min'))
    if budget_max:
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
    limit: int = 5000,
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
               ORDER BY COALESCE(l.updated_on, l.created_at) DESC, l.created_at DESC LIMIT %s OFFSET %s""",
            (limit, skip)
        )
        leads = cursor.fetchall()
        attach_current_assignees(cursor, leads)
        
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
              AND LOWER(IFNULL(l.lead_type, '')) IN ('seller', 'builder', 'landlord', 'owner', 'agent')
              AND (l.is_deleted IS NULL OR l.is_deleted = 0)
            ORDER BY l.created_at DESC
        """, (lead_id,))
        candidates = cursor.fetchall()
        attach_current_assignees(cursor, candidates)
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
        if inventory_type in ['seller', 'builder', 'agent']:
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
        attach_current_assignees(cursor, candidates)

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
    limit: int = 5000,
    current_user: dict = Depends(get_current_user)
):
    """Get INVENTORY leads (seller, landlord, builder) with floor pricing, scoring, and aging - excludes deleted"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT l.*, u.full_name as created_by_name 
               FROM leads l
               LEFT JOIN users u ON l.created_by = u.id
               WHERE l.lead_type IN ('seller', 'owner', 'landlord', 'builder', 'agent')
               AND (l.is_deleted IS NULL OR l.is_deleted = 0)
               ORDER BY COALESCE(l.updated_on, l.created_at) DESC, l.created_at DESC LIMIT %s OFFSET %s""",
            (limit, skip)
        )
        leads = cursor.fetchall()
        attach_current_assignees(cursor, leads)
        
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
        ensure_collaboration_tables(cursor)
        conn.commit()
        cursor.execute(
            """SELECT id, name, phone, email, lead_type, lead_status, location,
                      address, created_by, assigned_to
               FROM leads
               WHERE (is_deleted IS NULL OR is_deleted = 0)
               AND (name LIKE %s OR phone LIKE %s OR email LIKE %s)
               ORDER BY name ASC
               LIMIT 10""",
            (search_term, search_term, search_term)
        )
        leads = cursor.fetchall()
        attach_current_assignees(cursor, leads)

    return [
        apply_lead_masking(dict(lead), current_user.get('role', ''), current_user.get('id'))
        for lead in leads
    ]

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
        attach_current_assignees(cursor, leads)

    masked = [
        apply_lead_masking(dict(lead), current_user.get('role', ''), current_user.get('id'))
        for lead in leads
    ]
    return [LeadResponse(**lead) for lead in masked]

@api_router.get("/leads/map-data")
def get_leads_for_map(lead_type: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Get leads with location data for map view"""
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        conn.commit()
        
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
                       l.budget_min, l.budget_max, l.bhk, l.area_size, l.created_by, l.assigned_to,
                       loc.latitude, loc.longitude
                FROM leads l
                LEFT JOIN locations loc ON LOWER(l.location) LIKE CONCAT('%%', LOWER(loc.name), '%%')
                WHERE (l.is_deleted IS NULL OR l.is_deleted = 0)
                AND l.location IS NOT NULL AND l.location != ''
            """
        else:
            query = """
                SELECT l.id, l.name, l.lead_type, l.location, l.address, l.Property_locationUrl,
                       l.budget_min, l.budget_max, l.bhk, l.area_size, l.created_by, l.assigned_to,
                       NULL as latitude, NULL as longitude
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
        attach_current_assignees(cursor, leads)
        return [
            apply_lead_masking(dict(lead), current_user.get('role', ''), current_user.get('id'))
            for lead in leads
        ]

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
            query += " AND LOWER(IFNULL(lead_type, '')) IN ('seller', 'landlord', 'builder', 'owner', 'agent')"
        elif lead_type:
            query += " AND lead_type = %s"
            params.append(lead_type)

        query += " ORDER BY created_at DESC"
        cursor.execute(query, params)
        leads = cursor.fetchall()
        attach_current_assignees(cursor, leads)
        leads = [
            apply_lead_masking(dict(lead), current_user.get('role', ''), current_user.get('id'))
            for lead in leads
        ]
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

@api_router.get("/leads/{lead_id}")
def get_lead(lead_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
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
        attach_current_assignees(cursor, [lead])
        
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
    if lead.get('lead_type') in ['seller', 'owner', 'landlord', 'builder', 'agent'] and lead.get('area_size') and lead.get('location'):
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
                    m.assigned_to as property_assigned_to,
                    u.full_name as created_by_fullname,
                    u.phone as created_by_phone
                FROM preferred_leads pl
                LEFT JOIN leads m ON pl.matching_lead_id = m.id
                LEFT JOIN users u ON m.created_by = u.id
                WHERE pl.lead_id = %s
                ORDER BY pl.created_at DESC
            """, (lead_id,))
            matched_properties = cursor.fetchall()
            property_assignment_map = current_assignee_map(
                cursor,
                [prop.get('property_id') for prop in matched_properties if prop.get('property_id')]
            )
            
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
                prop['property_current_assignee_id'] = property_assignment_map.get(prop.get('property_id'))
                if should_mask_data(
                    current_user.get('role', ''),
                    current_user.get('id'),
                    prop.get('property_created_by'),
                    prop.get('property_current_assignee_id') or prop.get('property_assigned_to'),
                ):
                    prop['can_view_sensitive'] = False
                    if prop.get('property_phone'):
                        prop['property_phone'] = mask_phone(prop['property_phone'])
                    if prop.get('property_address'):
                        prop['property_address'] = mask_address(prop['property_address'])
                    prop['property_map_url'] = None
                    prop['created_by_phone'] = None
                else:
                    prop['can_view_sensitive'] = True
            
            response['matched_properties'] = matched_properties
    else:
        response['matched_properties'] = []
    
    return apply_lead_masking(response, current_user.get('role', ''), current_user.get('id'))

@api_router.post("/leads", response_model=LeadResponse)
def create_lead(lead: LeadCreate, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        floor_pricing = getattr(lead, 'floor_pricing', None) or []
        floor_amounts = []
        for price_row in floor_pricing:
            try:
                amount = float(price_row.get('price') or price_row.get('floor_amount') or 0)
                if amount > 0:
                    floor_amounts.append(amount)
            except (TypeError, ValueError):
                continue
        
        # Build insert query with all available fields
        fields = ['name', 'phone', 'email', 'lead_type', 'location', 'address', 'bhk', 
                  'budget_min', 'budget_max', 'property_type', 'lead_temperature', 'lead_status', 
                  'lead_source', 'notes', 'floor', 'area_size', 'car_parking_number', 'lift_available', 'unit',
                  'Property_locationUrl', 'building_facing', 'possession_on', 'property_age', 'builder_id',
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
            'budget_min': min(floor_amounts) if floor_amounts else lead.budget_min,
            'budget_max': max(floor_amounts) if floor_amounts else lead.budget_max,
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
            'property_age': getattr(lead, 'property_age', None),
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
        ensure_collaboration_tables(cursor)
        cursor.execute("SELECT created_by FROM leads WHERE id = %s", (lead_id,))
        existing_lead = cursor.fetchone()
        if not existing_lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        assignment_map = current_assignee_map(cursor, [lead_id])
        if should_mask_data(
            current_user.get('role', ''),
            current_user.get('id'),
            existing_lead.get('created_by'),
            assignment_map.get(lead_id),
        ):
            raise HTTPException(status_code=403, detail="Only the lead creator or current assignee can edit this lead")
        
        # Build dynamic update query based on provided fields
        update_fields = []
        values = []
        
        allowed_fields = [
            'name', 'phone', 'email', 'lead_type', 'location', 'address',
            'bhk', 'budget_min', 'budget_max', 'property_type',
            'lead_temperature', 'lead_status', 'lead_source', 'notes', 'floor', 'area_size',
            'car_parking_number', 'lift_available', 'unit', 'Property_locationUrl',
            'building_facing', 'possession_on', 'property_age', 'builder_id',
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
        lead_update_rowcount = cursor.rowcount
        conn.commit()
        
        # Keep the lead-level price range aligned with Web LMS floor pricing behavior.
        if 'floor_pricing' in lead_data:
            floor_amounts = []
            for price_row in lead_data.get('floor_pricing') or []:
                try:
                    amount = float(price_row.get('price') or price_row.get('floor_amount') or 0)
                    if amount > 0:
                        floor_amounts.append(amount)
                except (TypeError, ValueError):
                    continue
            if floor_amounts:
                cursor.execute(
                    "UPDATE leads SET budget_min = %s, budget_max = %s WHERE id = %s",
                    (min(floor_amounts), max(floor_amounts), lead_id),
                )

            # Delete existing floor pricing
            cursor.execute("DELETE FROM inventory_floor_pricing WHERE lead_id = %s", (lead_id,))
            
            # Insert new floor pricing
            for fp in lead_data.get('floor_pricing') or []:
                if fp.get('floor') and fp.get('price'):
                    cursor.execute(
                        """INSERT INTO inventory_floor_pricing (lead_id, floor_label, floor_amount)
                           VALUES (%s, %s, %s)""",
                        (lead_id, fp['floor'], float(fp['price']))
                    )
            conn.commit()
        
        if lead_update_rowcount == 0:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        cursor.execute("SELECT * FROM leads WHERE id = %s", (lead_id,))
        updated = cursor.fetchone()
    
    return updated

@api_router.delete("/leads/{lead_id}")
def delete_lead(lead_id: int, current_user: dict = Depends(get_current_user)):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            ensure_collaboration_tables(cursor)
            cursor.execute("SELECT created_by FROM leads WHERE id = %s", (lead_id,))
            existing_lead = cursor.fetchone()
            if not existing_lead:
                raise HTTPException(status_code=404, detail="Lead not found")
            assignment_map = current_assignee_map(cursor, [lead_id])
            if should_mask_data(
                current_user.get('role', ''),
                current_user.get('id'),
                existing_lead.get('created_by'),
                assignment_map.get(lead_id),
            ):
                raise HTTPException(status_code=403, detail="Only the lead creator or current assignee can delete this lead")
            
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
        attach_current_assignees(cursor, leads)

    return [
        apply_lead_masking(dict(lead), current_user.get('role', ''), current_user.get('id'))
        for lead in leads
    ]

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
def ensure_followups_soft_delete_column(cursor):
    try:
        cursor.execute("SHOW COLUMNS FROM followups LIKE 'is_deleted'")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE followups ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0")
    except Exception as exc:
        logging.warning(f"Followup soft-delete column guard skipped: {exc}")

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
        ensure_followups_soft_delete_column(cursor)
        conn.commit()
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
        ensure_followups_soft_delete_column(cursor)
        conn.commit()
        
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

# ============= WhatsApp Tracking Routes =============
@api_router.post("/whatsapp/send")
def log_whatsapp_action(data: WhatsAppMessageCreate, current_user: dict = Depends(get_current_user)):
    """Record that the mobile app opened WhatsApp for a lead/contact."""
    clean_phone = re.sub(r'[^0-9]', '', data.phone or '')
    phone_key = clean_phone[-10:] if clean_phone else ''
    lead_id = int(data.lead_id) if data.lead_id and str(data.lead_id).isdigit() else None
    status_value = (data.status or "opened")[:50]

    with get_db() as conn:
        cursor = conn.cursor()
        ensure_whatsapp_tracking_columns(cursor)
        ensure_whatsapp_logs_table(cursor)

        cursor.execute("""
            INSERT INTO whatsapp_logs (lead_id, phone, message, status, source, created_by, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
        """, (lead_id, data.phone, data.message, status_value, data.source or "ios_app", current_user['id']))

        updated = 0
        if lead_id:
            cursor.execute("""
                UPDATE leads
                SET last_message_sent_on = NOW(),
                    last_sent_message = %s,
                    whatsapp_sent_flag = 1,
                    updated_on = CASE
                        WHEN LOWER(IFNULL(lead_type, '')) IN ('seller', 'owner', 'landlord', 'builder', 'agent') THEN updated_on
                        ELSE NOW()
                    END
                WHERE id = %s
            """, (data.message, lead_id))
            updated += cursor.rowcount

        if phone_key:
            cursor.execute("""
                UPDATE leads
                SET last_message_sent_on = NOW(),
                    last_sent_message = %s,
                    whatsapp_sent_flag = 1,
                    updated_on = CASE
                        WHEN LOWER(IFNULL(lead_type, '')) IN ('seller', 'owner', 'landlord', 'builder', 'agent') THEN updated_on
                        ELSE NOW()
                    END
                WHERE RIGHT(REGEXP_REPLACE(IFNULL(phone, ''), '[^0-9]', ''), 10) = %s
            """, (data.message, phone_key))
            updated += cursor.rowcount

        conn.commit()

    return {"success": True, "status": status_value, "updated": updated}

@api_router.get("/whatsapp/logs")
def get_whatsapp_logs(lead_id: Optional[int] = None, limit: int = 100, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_whatsapp_logs_table(cursor)
        safe_limit = max(1, min(int(limit or 100), 200))
        columns = _table_columns(cursor, 'whatsapp_logs')
        message_expr = (
            "COALESCE(wl.message, wl.message_body)"
            if {'message', 'message_body'}.issubset(columns)
            else "wl.message"
            if 'message' in columns
            else "wl.message_body"
            if 'message_body' in columns
            else "''"
        )
        date_expr = (
            "COALESCE(wl.created_at, wl.sent_at)"
            if {'created_at', 'sent_at'}.issubset(columns)
            else "wl.created_at"
            if 'created_at' in columns
            else "wl.sent_at"
            if 'sent_at' in columns
            else "NULL"
        )
        phone_expr = "wl.phone" if 'phone' in columns else "NULL"
        params: List[Any] = []
        where = ""
        if lead_id:
            where = "WHERE wl.lead_id = %s"
            params.append(lead_id)
        cursor.execute(f"""
            SELECT wl.id, wl.lead_id, {phone_expr} as phone,
                   {message_expr} as message,
                   wl.status, wl.source, wl.created_by,
                   {date_expr} as created_at,
                   u.full_name as created_by_name
            FROM whatsapp_logs wl
            LEFT JOIN users u ON wl.created_by = u.id
            {where}
            ORDER BY {date_expr} DESC
            LIMIT %s
        """, [*params, safe_limit])
        logs = cursor.fetchall()
        lead_ids = [row.get('lead_id') for row in logs if row.get('lead_id')]
        assignment_map = current_assignee_map(cursor, lead_ids)
        creator_map: Dict[int, Optional[int]] = {}
        if lead_ids:
            clean_ids = sorted({int(item) for item in lead_ids})
            placeholders = ','.join(['%s'] * len(clean_ids))
            cursor.execute(
                f"SELECT id, created_by FROM leads WHERE id IN ({placeholders})",
                clean_ids,
            )
            creator_map = {int(row['id']): row.get('created_by') for row in cursor.fetchall()}

    result = []
    for log in logs:
        item = dict(log)
        log_lead_id = item.get('lead_id')
        if should_mask_data(
            current_user.get('role', ''),
            current_user.get('id'),
            creator_map.get(int(log_lead_id)) if log_lead_id else None,
            assignment_map.get(int(log_lead_id)) if log_lead_id else None,
        ) and item.get('phone'):
            item['phone'] = mask_phone(item['phone'])
        result.append(item)
    return result

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
        ensure_action_assignment_column(cursor)
        conn.commit()
        cursor.execute(
            """SELECT a.*, l.name as lead_name, l.phone as lead_phone, l.created_by as lead_created_by,
                      creator.full_name as created_by_name, creator.username as created_by_username,
                      assignee.full_name as assigned_to_name, assignee.username as assigned_to_username
               FROM actions a
               LEFT JOIN leads l ON a.lead_id = l.id
               LEFT JOIN users creator ON creator.id = a.user_id
               LEFT JOIN users assignee ON assignee.id = a.assigned_to
               WHERE a.user_id = %s OR a.assigned_to = %s
               ORDER BY a.due_date ASC, a.due_time ASC LIMIT %s OFFSET %s""",
            (current_user['id'], current_user['id'], limit, skip)
        )
        actions = cursor.fetchall()
        assignment_map = current_assignee_map(
            cursor,
            [action.get('lead_id') for action in actions if action.get('lead_id')]
        )
        
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
        item['lead_current_assignee_id'] = (
            assignment_map.get(int(item['lead_id'])) if item.get('lead_id') else None
        )
        item['can_view_sensitive'] = not should_mask_data(
            user_role,
            user_id,
            lead_created_by,
            item.get('lead_current_assignee_id'),
        )
        if not item['can_view_sensitive']:
            if item.get('lead_phone'):
                item['lead_phone'] = mask_phone(item['lead_phone'])
    
    return result

@api_router.post("/reminders")
def create_reminder(reminder: ReminderCreate, current_user: dict = Depends(get_current_user)):
    """Create a new action/reminder in the actions table"""
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_action_assignment_column(cursor)
        
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
        assigned_to = reminder.assigned_to or current_user['id']
        cursor.execute(
            """INSERT INTO actions (user_id, assigned_to, lead_id, title, description, action_type, due_date, due_time, status, priority, is_notified)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (current_user['id'], assigned_to, reminder.lead_id, reminder.title, reminder.notes,
             reminder.reminder_type, date_part, time_part, status, reminder.priority or 'Medium', 0)
        )
        conn.commit()
        action_id = cursor.lastrowid
        
        cursor.execute(
            """SELECT a.*, l.name as lead_name, l.phone as lead_phone,
                      creator.full_name as created_by_name, creator.username as created_by_username,
                      assignee.full_name as assigned_to_name, assignee.username as assigned_to_username
               FROM actions a
               LEFT JOIN leads l ON a.lead_id = l.id
               LEFT JOIN users creator ON creator.id = a.user_id
               LEFT JOIN users assignee ON assignee.id = a.assigned_to
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
        ensure_action_assignment_column(cursor)
        
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
        
        allowed_fields = ['title', 'due_date', 'due_time', 'action_type', 'description', 'status', 'lead_id', 'assigned_to', 'priority', 'outcome', 'completed_at', 'is_notified']
        
        for field in allowed_fields:
            if field in reminder_data:
                update_fields.append(f"{field} = %s")
                values.append(reminder_data[field])
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        values.append(reminder_id)
        if current_user.get('role') == 'admin':
            query = f"UPDATE actions SET {', '.join(update_fields)} WHERE id = %s"
        else:
            values.append(current_user['id'])
            values.append(current_user['id'])
            query = f"UPDATE actions SET {', '.join(update_fields)} WHERE id = %s AND (user_id = %s OR assigned_to = %s)"
        
        cursor.execute(query, values)
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Action/Reminder not found")
        
        cursor.execute(
            """SELECT a.*, l.name as lead_name, l.phone as lead_phone,
                      creator.full_name as created_by_name, creator.username as created_by_username,
                      assignee.full_name as assigned_to_name, assignee.username as assigned_to_username
               FROM actions a
               LEFT JOIN leads l ON a.lead_id = l.id
               LEFT JOIN users creator ON creator.id = a.user_id
               LEFT JOIN users assignee ON assignee.id = a.assigned_to
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
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE lead_type IN ('seller', 'owner', 'landlord', 'builder', 'agent') AND (is_deleted IS NULL OR is_deleted = 0)")
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
            WHERE lead_type IN ('seller', 'owner', 'landlord', 'builder', 'agent')
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
    user_role = current_user.get('role', '')
    user_id = current_user.get('id')
    
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_whatsapp_tracking_columns(cursor)
        conn.commit()
        
        # Get active buyers with preferences
        cursor.execute("""
            SELECT id, name, phone, location, budget_min, budget_max, floor, bhk,
                   building_facing, property_type, lead_type, lead_status,
                   lead_temperature, created_by, updated_on
            FROM leads 
            WHERE lead_type IN ('buyer', 'tenant') 
            AND lead_status NOT IN ('Won', 'Closed/Lost', 'Lost')
            AND (is_deleted IS NULL OR is_deleted = 0)
            ORDER BY
              CASE WHEN lead_temperature = 'Hot' THEN 0 WHEN lead_temperature = 'Warm' THEN 1 ELSE 2 END,
              updated_on DESC
            LIMIT 40
        """)
        buyers = cursor.fetchall()
        attach_current_assignees(cursor, buyers)
        
        # Get available inventory
        cursor.execute("""
            SELECT id, name, phone, location, budget_min, budget_max, floor, bhk,
                   building_facing, property_type, area_size, lead_type,
                   lead_status, created_by, updated_on
            FROM leads 
            WHERE lead_type IN ('seller', 'owner', 'landlord', 'builder', 'agent')
            AND lead_status NOT IN ('Sold', 'Closed/Lost', 'Lost')
            AND (is_deleted IS NULL OR is_deleted = 0)
            ORDER BY updated_on DESC
            LIMIT 100
        """)
        inventory = cursor.fetchall()
        attach_current_assignees(cursor, inventory)

        buyer_ids = [row['id'] for row in buyers]
        saved_pairs = set()
        if buyer_ids:
            placeholders = ','.join(['%s'] * len(buyer_ids))
            cursor.execute(f"""
                SELECT lead_id, matching_lead_id
                FROM preferred_leads
                WHERE lead_id IN ({placeholders})
                  AND matching_lead_id IS NOT NULL
            """, buyer_ids)
            saved_pairs = {(row['lead_id'], row['matching_lead_id']) for row in cursor.fetchall()}
        
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
                    buyer_item = dict(buyer)
                    inventory_item = dict(inv)
                    buyer_item = apply_lead_masking(buyer_item, user_role, user_id)
                    inventory_item = apply_lead_masking(inventory_item, user_role, user_id)
                    saved = (buyer['id'], inv['id']) in saved_pairs
                    if saved:
                        score += 8
                        reasons.insert(0, "Already preferred")

                    matches.append({
                        'buyer_id': buyer['id'],
                        'buyer_name': buyer['name'],
                        'buyer_type': buyer.get('lead_type'),
                        'buyer_phone': buyer_item.get('phone'),
                        'buyer_status': buyer.get('lead_status'),
                        'buyer_temperature': buyer.get('lead_temperature'),
                        'buyer_budget_min': buyer.get('budget_min'),
                        'buyer_budget_max': buyer.get('budget_max'),
                        'inventory_id': inv['id'],
                        'inventory_name': inv['name'] or f"Inventory #{inv['id']}",
                        'inventory_type': inv.get('lead_type'),
                        'inventory_phone': inventory_item.get('phone'),
                        'inventory_status': inv.get('lead_status'),
                        'inventory_price_min': inv.get('budget_min'),
                        'inventory_price_max': inv.get('budget_max'),
                        'inventory_floor': inv.get('floor'),
                        'inventory_bhk': inv.get('bhk'),
                        'inventory_area_size': inv.get('area_size'),
                        'location': inv.get('location') or 'N/A',
                        'match_score': min(score, 100),
                        'match_reasons': reasons,
                        'is_saved': saved,
                        'is_hot': buyer.get('lead_temperature') == 'Hot' or score >= 80,
                        'updated_on': inv['updated_on'].isoformat() if inv.get('updated_on') else None
                    })
        
        # Sort by score and return top matches
        matches.sort(key=lambda x: (not x['is_saved'], -x['match_score'], x.get('updated_on') or ''), reverse=False)
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
        assignment_map = current_assignee_map(
            cursor,
            [item.get('lead_id') for item in followups if item.get('lead_id')]
        )
        
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
                'created_by': f['created_by'],
                'current_assignee_id': assignment_map.get(int(f['lead_id']))
            })
        
        # Apply masking to phone numbers based on user permissions
        user_role = current_user.get('role', '')
        user_id = current_user.get('id')
        for item in result:
            created_by = item.get('created_by')
            item['can_view_sensitive'] = not should_mask_data(
                user_role,
                user_id,
                created_by,
                item.get('current_assignee_id'),
            )
            if not item['can_view_sensitive']:
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
            INSERT INTO plot_pricing (location_id, circle, plot_size, price_per_sq_yard, min_price, max_price, tentative_price)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (pricing.location_id, pricing.circle, pricing.plot_size, pricing.price_per_sq_yard,
              pricing.min_price, pricing.max_price, pricing.tentative_price))
        conn.commit()
        
        plot_pricing_id = cursor.lastrowid
        
        # Insert floor pricing
        for floor in pricing.floors:
            if floor.get('floor_label') and floor.get('tentative_floor_price'):
                cursor.execute("""
                    INSERT INTO plot_floor_pricing (plot_pricing_id, floor_label, tentative_floor_price)
                    VALUES (%s, %s, %s)
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
                        INSERT INTO plot_floor_pricing (plot_pricing_id, floor_label, tentative_floor_price)
                        VALUES (%s, %s, %s)
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
            assignment_map = current_assignee_map(
                cursor,
                [visit.get('lead_id') for visit in visits if visit.get('lead_id')]
            )
            result = []
            for visit in visits:
                item = dict(visit)
                item['lead_current_assignee_id'] = assignment_map.get(int(item['lead_id'])) if item.get('lead_id') else None
                item['can_view_sensitive'] = not should_mask_data(
                    current_user.get('role', ''),
                    current_user.get('id'),
                    item.get('lead_created_by'),
                    item.get('lead_current_assignee_id'),
                )
                if not item['can_view_sensitive']:
                    if item.get('lead_phone'):
                        item['lead_phone'] = mask_phone(item['lead_phone'])
                    item['property_map_url'] = None
                    item['location_url'] = None
                result.append(item)
            return result
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


def ensure_deals_table(cursor, conn):
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

    column_definitions = {
        'property_lead_id': 'INT',
        'commission_amount': 'DECIMAL(15,2)',
        'status': "VARCHAR(50) DEFAULT 'Negotiation'",
        'payment_received': 'DECIMAL(15,2) DEFAULT 0',
        'notes': 'TEXT',
        'expected_closing_date': 'DATE',
        'created_by': 'INT',
        'created_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP',
    }
    for column, definition in column_definitions.items():
        try:
            cursor.execute(f"ALTER TABLE deals ADD COLUMN {column} {definition}")
            conn.commit()
        except Exception:
            pass


@api_router.get("/deals")
def get_deals(current_user: dict = Depends(get_current_user), status: Optional[str] = None):
    """Get all deals"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            ensure_deals_table(cursor, conn)
            
            # Check if property_lead_id column exists
            cursor.execute("SHOW COLUMNS FROM deals LIKE 'property_lead_id'")
            has_property_lead_id = cursor.fetchone() is not None
            
            if has_property_lead_id:
                query = """
                    SELECT d.*, 
                           l.name as lead_name, l.phone as lead_phone, l.created_by as lead_created_by,
                           p.name as property_name, p.location as property_location
                    FROM deals d
                    LEFT JOIN leads l ON d.lead_id = l.id
                    LEFT JOIN leads p ON d.property_lead_id = p.id
                    WHERE 1=1
                """
            else:
                query = """
                    SELECT d.*, 
                           l.name as lead_name, l.phone as lead_phone, l.created_by as lead_created_by,
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
            assignment_map = current_assignee_map(
                cursor,
                [deal.get('lead_id') for deal in deals if deal.get('lead_id')]
            )
            result = []
            for deal in deals:
                item = dict(deal)
                if should_mask_data(
                    current_user.get('role', ''),
                    current_user.get('id'),
                    item.get('lead_created_by'),
                    assignment_map.get(int(item['lead_id'])) if item.get('lead_id') else None,
                ) and item.get('lead_phone'):
                    item['lead_phone'] = mask_phone(item['lead_phone'])
                result.append(item)
            return result
    except Exception as e:
        logging.error(f"Deals error: {e}")
        return []

@api_router.post("/deals")
def create_deal(deal: DealCreate, current_user: dict = Depends(get_current_user)):
    """Create a new deal"""
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_deals_table(cursor, conn)
        commission = deal.commission_amount or (deal.deal_amount * deal.commission_percent / 100 if deal.deal_amount and deal.commission_percent else 0)
        deal_status = deal.status or 'Negotiation'
        cursor.execute("""
            INSERT INTO deals (lead_id, property_lead_id, deal_amount, commission_percent, commission_amount, 
            status, payment_received, notes, expected_closing_date, created_by, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (deal.lead_id, deal.property_lead_id, deal.deal_amount, deal.commission_percent, commission,
              deal_status, deal.payment_received or 0, deal.notes, deal.expected_closing_date, current_user['id']))
        deal_id = cursor.lastrowid
        if deal_status in ('Closed', 'Payment'):
            cursor.execute("UPDATE leads SET lead_status = 'Won' WHERE id = %s", (deal.lead_id,))
            if deal.property_lead_id:
                cursor.execute("UPDATE leads SET lead_status = 'Sold' WHERE id = %s", (deal.property_lead_id,))
        conn.commit()
        return {"id": deal_id, "message": "Conversion logged successfully"}

@api_router.put("/deals/{deal_id}")
def update_deal(deal_id: int, deal: DealCreate, current_user: dict = Depends(get_current_user)):
    """Update a deal"""
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_deals_table(cursor, conn)
        commission = deal.commission_amount or (deal.deal_amount * deal.commission_percent / 100 if deal.deal_amount and deal.commission_percent else 0)
        deal_status = deal.status or 'Negotiation'
        cursor.execute("""
            UPDATE deals SET lead_id=%s, property_lead_id=%s, deal_amount=%s, commission_percent=%s, 
            commission_amount=%s, status=%s, payment_received=%s, notes=%s, expected_closing_date=%s
            WHERE id=%s
        """, (deal.lead_id, deal.property_lead_id, deal.deal_amount, deal.commission_percent, commission,
              deal_status, deal.payment_received, deal.notes, deal.expected_closing_date, deal_id))
        if deal_status in ('Closed', 'Payment'):
            cursor.execute("UPDATE leads SET lead_status = 'Won' WHERE id = %s", (deal.lead_id,))
            if deal.property_lead_id:
                cursor.execute("UPDATE leads SET lead_status = 'Sold' WHERE id = %s", (deal.property_lead_id,))
        conn.commit()
        return {"message": "Conversion updated successfully"}

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
        cursor.execute("SELECT created_by FROM leads WHERE id = %s", (lead_id,))
        lead_owner = cursor.fetchone() or {}
        assignment_map = current_assignee_map(cursor, [lead_id])
        can_view_sensitive = not should_mask_data(
            current_user.get('role', ''),
            current_user.get('id'),
            lead_owner.get('created_by'),
            assignment_map.get(lead_id),
        )

        # Get conversation logs from followups table.
        try:
            ensure_followups_soft_delete_column(cursor)
            conn.commit()
            cursor.execute("""
                SELECT f.id, f.channel, f.outcome, f.notes, f.followup_date, f.next_followup,
                       f.created_at, u.full_name as owner_name
                FROM followups f
                LEFT JOIN users u ON u.id = f.owner_id
                WHERE f.lead_id = %s AND (f.is_deleted IS NULL OR f.is_deleted = 0)
                ORDER BY f.created_at DESC
            """, (lead_id,))
            for f in cursor.fetchall():
                channel = f.get('channel') or 'Conversation'
                outcome = f.get('outcome') or 'Logged'
                activities.append({
                    'type': 'conversation',
                    'id': f['id'],
                    'title': f"{channel}: {outcome}",
                    'description': f.get('notes') or '',
                    'date': f['created_at'].isoformat() if f.get('created_at') else str(f.get('followup_date') or ''),
                    'status': outcome,
                    'created_by': f.get('owner_name'),
                    'icon': 'chatbubbles',
                    'meta': {
                        'channel': channel,
                        'next_followup': f['next_followup'].isoformat() if f.get('next_followup') else None,
                    }
                })
        except Exception as exc:
            logging.warning(f"Followup timeline skipped for lead {lead_id}: {exc}")

        # Get WhatsApp opens/logs.
        try:
            ensure_whatsapp_logs_table(cursor)
            conn.commit()
            whatsapp_columns = _table_columns(cursor, 'whatsapp_logs')
            whatsapp_message_expr = (
                "COALESCE(wl.message, wl.message_body)"
                if {'message', 'message_body'}.issubset(whatsapp_columns)
                else "wl.message"
                if 'message' in whatsapp_columns
                else "wl.message_body"
                if 'message_body' in whatsapp_columns
                else "''"
            )
            whatsapp_date_expr = (
                "COALESCE(wl.created_at, wl.sent_at)"
                if {'created_at', 'sent_at'}.issubset(whatsapp_columns)
                else "wl.created_at"
                if 'created_at' in whatsapp_columns
                else "wl.sent_at"
                if 'sent_at' in whatsapp_columns
                else "NULL"
            )
            whatsapp_phone_expr = "wl.phone" if 'phone' in whatsapp_columns else "NULL"
            cursor.execute("""
                SELECT wl.id, {phone_expr} as phone, {message_expr} as message,
                       wl.status, wl.source, {date_expr} as created_at,
                       u.full_name as created_by_name
                FROM whatsapp_logs wl
                LEFT JOIN users u ON u.id = wl.created_by
                WHERE wl.lead_id = %s
                ORDER BY {date_expr} DESC
            """.format(
                phone_expr=whatsapp_phone_expr,
                message_expr=whatsapp_message_expr,
                date_expr=whatsapp_date_expr,
            ), (lead_id,))
            for w in cursor.fetchall():
                activities.append({
                    'type': 'whatsapp',
                    'id': w['id'],
                    'title': 'WhatsApp opened',
                    'description': w.get('message') or '',
                    'date': w['created_at'].isoformat() if w.get('created_at') else '',
                    'status': w.get('status') or 'opened',
                    'created_by': w.get('created_by_name'),
                    'icon': 'logo-whatsapp',
                    'meta': {
                        'phone': w.get('phone') if can_view_sensitive else mask_phone(w.get('phone')),
                        'source': w.get('source'),
                    }
                })
        except Exception as exc:
            logging.warning(f"WhatsApp timeline skipped for lead {lead_id}: {exc}")
        
        # Get follow-ups/actions
        cursor.execute("""
            SELECT 'action' as type, id, title, description, action_type, due_date as activity_date, 
                   status, created_at, NULL as created_by_name
            FROM actions WHERE lead_id = %s
            ORDER BY created_at DESC
        """, (lead_id,))
        followups = cursor.fetchall()
        for f in followups:
            activities.append({
                'type': 'action',
                'id': f['id'],
                'title': f.get('title') or f.get('action_type') or 'Follow-up',
                'description': f.get('description') or '',
                'date': str(f['activity_date']) if f.get('activity_date') else (f['created_at'].isoformat() if f.get('created_at') else ''),
                'status': f['status'],
                'icon': 'calendar'
            })
        
        # Get site visits
        cursor.execute("""
            SELECT 'visit' as type, id, CONCAT('Site Visit: ', COALESCE(location, 'Property')) as description,
                   visit_date as activity_date, status, created_at
            FROM site_visits WHERE lead_id = %s OR property_lead_id = %s
            ORDER BY created_at DESC
        """, (lead_id, lead_id))
        visits = cursor.fetchall()
        for v in visits:
            activities.append({
                'type': 'visit',
                'id': v['id'],
                'title': 'Site Visit',
                'description': v['description'],
                'date': str(v['activity_date']) if v.get('activity_date') else (v['created_at'].isoformat() if v.get('created_at') else ''),
                'status': v['status'],
                'icon': 'location'
            })
        
        # Get deals/conversions. Existing LMS databases may use deal_value,
        # final_deal_value, deal_status, inventory_id, or property_id.
        try:
            if _table_exists(cursor, 'deals'):
                deal_columns = _table_columns(cursor, 'deals')
                amount_candidates = [col for col in ['deal_amount', 'deal_value', 'final_deal_value'] if col in deal_columns]
                amount_expr = f"COALESCE({', '.join(amount_candidates)}, 0)" if amount_candidates else "0"
                status_expr = (
                    "COALESCE(status, deal_status)"
                    if {'status', 'deal_status'}.issubset(deal_columns)
                    else "status"
                    if 'status' in deal_columns
                    else "deal_status"
                    if 'deal_status' in deal_columns
                    else "'Logged'"
                )
                date_expr = "expected_closing_date" if 'expected_closing_date' in deal_columns else "created_at"
                created_expr = "created_at" if 'created_at' in deal_columns else "NULL"
                related_columns = [col for col in ['lead_id', 'property_lead_id', 'inventory_id', 'property_id'] if col in deal_columns]
                if related_columns:
                    where_clause = " OR ".join([f"{col} = %s" for col in related_columns])
                    params = tuple([lead_id] * len(related_columns))
                    cursor.execute(f"""
                        SELECT 'deal' as type, id, CONCAT('Deal: ₹', {amount_expr}, ' Cr') as description,
                               {date_expr} as activity_date, {status_expr} as status, {created_expr} as created_at
                        FROM deals WHERE {where_clause}
                        ORDER BY {created_expr} DESC
                    """, params)
                    for d in cursor.fetchall():
                        activities.append({
                            'type': 'deal',
                            'id': d['id'],
                            'title': 'Conversion',
                            'description': d['description'],
                            'date': str(d['activity_date']) if d.get('activity_date') else (d['created_at'].isoformat() if d.get('created_at') else ''),
                            'status': d.get('status') or 'Logged',
                            'icon': 'cash'
                        })
        except Exception as exc:
            logging.warning(f"Deals timeline skipped for lead {lead_id}: {exc}")
    
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

# ============= Mobile Workbench Routes =============
def _table_exists(cursor, table_name: str) -> bool:
    cursor.execute(
        """SELECT COUNT(*) as count
           FROM information_schema.tables
           WHERE table_schema = DATABASE() AND table_name = %s""",
        (table_name,)
    )
    row = cursor.fetchone()
    return bool(row and row.get('count'))

def _table_columns(cursor, table_name: str) -> set:
    cursor.execute(
        """SELECT column_name
           FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = %s""",
        (table_name,)
    )
    return {row['column_name'] for row in cursor.fetchall()}

def _pick_column(columns: set, candidates: List[str]) -> Optional[str]:
    for item in candidates:
        if item in columns:
            return item
    return None

def _lead_summary(row: dict, user_role: str, user_id: int) -> dict:
    lead = apply_lead_masking(dict(row), user_role, user_id)
    return {
        "id": lead.get("id"),
        "name": lead.get("name"),
        "phone": lead.get("phone"),
        "lead_type": lead.get("lead_type"),
        "lead_temperature": lead.get("lead_temperature"),
        "lead_status": lead.get("lead_status"),
        "location": lead.get("location"),
        "address": lead.get("address"),
        "bhk": lead.get("bhk"),
        "floor": lead.get("floor"),
        "area_size": lead.get("area_size"),
        "budget_min": lead.get("budget_min"),
        "budget_max": lead.get("budget_max"),
        "unit": lead.get("unit"),
        "created_by": lead.get("created_by"),
        "created_by_name": lead.get("created_by_name"),
        "assigned_to": lead.get("assigned_to"),
        "current_assignee_id": lead.get("current_assignee_id"),
        "assigned_to_name": lead.get("assigned_to_name"),
        "can_view_sensitive": lead.get("can_view_sensitive"),
        "created_at": lead.get("created_at").isoformat() if lead.get("created_at") else None,
    }

def _build_whatsapp_intelligence(row: dict) -> dict:
    name = row.get("name") or "there"
    lead_type = (row.get("lead_type") or "").lower()
    location = row.get("location") or row.get("address") or "your preferred area"
    status = row.get("lead_status") or "Open"
    temperature = row.get("lead_temperature") or ""
    days_since = row.get("days_since_whatsapp")
    whatsapp_count = int(row.get("whatsapp_log_count") or 0)
    pending_actions = int(row.get("pending_action_count") or 0)

    if days_since is None:
        reason = "Never messaged on WhatsApp"
        priority = "High"
        next_days = 1
    elif days_since >= 10:
        reason = f"No WhatsApp touch for {days_since} days"
        priority = "High" if temperature == "Hot" else "Medium"
        next_days = 2
    elif days_since >= 3:
        reason = f"Follow-up due after {days_since} days"
        priority = "Medium"
        next_days = 3
    else:
        reason = "Recent WhatsApp touch"
        priority = "Low"
        next_days = 3

    if pending_actions == 0 and priority != "High":
        priority = "Medium"

    if lead_type in ("seller", "landlord", "builder", "agent"):
        suggested = (
            f"Hi {name}, checking if your property in {location} is still available. "
            "Please confirm current price, availability, and any updated details."
        )
    elif whatsapp_count == 0:
        suggested = (
            f"Hi {name}, we have suitable property options for {location}. "
            "Please share your preferred time for a quick call or site visit."
        )
    elif temperature == "Hot":
        suggested = (
            f"Hi {name}, following up on your property requirement in {location}. "
            "Should I arrange the next site visit or share updated matching options today?"
        )
    else:
        suggested = (
            f"Hi {name}, just following up on your {status.lower()} property requirement in {location}. "
            "Please let me know if you would like fresh options."
        )

    return {
        "whatsapp_reason": reason,
        "whatsapp_priority": priority,
        "suggested_message": suggested,
        "suggested_next_followup_days": next_days,
        "pending_action_count": pending_actions,
        "whatsapp_log_count": whatsapp_count,
    }

def _find_enquiry_table(cursor) -> Optional[dict]:
    for table in ["enquiries", "telecaller_enquiries", "advertised_enquiries", "advt_enquiries", "advertised_leads", "advt_leads", "ad_enquiries"]:
        if not _table_exists(cursor, table):
            continue
        columns = _table_columns(cursor, table)
        id_col = _pick_column(columns, ["id", "enquiry_id"])
        name_col = _pick_column(columns, ["name", "client_name", "lead_name", "full_name"])
        phone_col = _pick_column(columns, ["phone", "mobile", "phone_number", "contact", "contact_number"])
        if id_col and name_col and phone_col:
            return {
                "table": table,
                "columns": columns,
                "id": id_col,
                "name": name_col,
                "phone": phone_col,
                "location": _pick_column(columns, ["location", "preferred_location", "area"]),
                "notes": _pick_column(columns, ["notes", "note", "message", "remarks"]),
                "status": _pick_column(columns, ["status", "lead_status"]),
                "source": _pick_column(columns, ["source", "lead_source", "platform"]),
                "created_at": _pick_column(columns, ["created_at", "Updated_On", "created_on", "date", "enquiry_date"]),
                "lead_type": _pick_column(columns, ["lead_type"]),
                "bhk": _pick_column(columns, ["bhk", "flat_type"]),
                "floor": _pick_column(columns, ["floor"]),
                "budget_min": _pick_column(columns, ["budget_min", "budget"]),
                "budget_max": _pick_column(columns, ["budget_max", "budget"]),
                "unit": _pick_column(columns, ["unit"]),
                "property_type": _pick_column(columns, ["property_type", "flat_type"]),
                "is_deleted": _pick_column(columns, ["is_deleted"]),
                "converted": _pick_column(columns, ["converted", "is_converted", "converted_to_lead"]),
            }
    return None

def _enquiry_where_clause(meta: dict) -> str:
    clauses = []
    converted_col = meta.get("converted")
    deleted_col = meta.get("is_deleted")
    if converted_col:
        clauses.append(f"COALESCE({converted_col}, 0) = 0")
    if deleted_col:
        clauses.append(f"COALESCE({deleted_col}, 0) = 0")
    return " AND ".join(clauses) if clauses else "1=1"

def _enquiry_select_parts(meta: dict, include_details: bool = True) -> List[str]:
    select_parts = [
        f"{meta['id']} as id",
        f"{meta['name']} as name",
        f"{meta['phone']} as phone",
    ]
    aliases = ["location", "notes", "status", "source", "created_at"]
    if include_details:
        aliases += ["lead_type", "bhk", "floor", "budget_min", "budget_max", "unit", "property_type"]
    for alias in aliases:
        col = meta.get(alias)
        select_parts.append(f"{col} as {alias}" if col else f"NULL as {alias}")
    return select_parts

def _legacy_inventory_category(row: dict) -> str:
    type_text = " ".join([
        str(row.get("property_type") or ""),
        str(row.get("bhk") or ""),
        str(row.get("lead_type") or ""),
    ]).lower()
    if "floor" in type_text or "bhk" in type_text:
        return "floor"
    return "kothi"

def _legacy_inventory_category_clause(meta: dict, category: Optional[str]) -> str:
    if category not in ("kothi", "floor"):
        return ""
    type_columns = [meta.get("property_type"), meta.get("bhk"), meta.get("lead_type")]
    type_columns = [col for col in type_columns if col]
    if not type_columns:
        return ""
    floor_checks = " OR ".join([f"LOWER(COALESCE({col}, '')) LIKE %s OR LOWER(COALESCE({col}, '')) LIKE %s" for col in type_columns])
    if category == "floor":
        return f" AND ({floor_checks})"
    return f" AND NOT ({floor_checks})"

def _legacy_inventory_category_params(meta: dict, category: Optional[str]) -> List[str]:
    if category not in ("kothi", "floor"):
        return []
    type_columns = [meta.get("property_type"), meta.get("bhk"), meta.get("lead_type")]
    type_columns = [col for col in type_columns if col]
    return [value for _ in type_columns for value in ("%floor%", "%bhk%")]

def _legacy_floor_where() -> str:
    return """(e.is_deleted != 1 OR e.is_deleted IS NULL)
              AND (e.phone IS NULL OR e.phone NOT IN (
                  SELECT b.phone FROM builders b WHERE b.phone IS NOT NULL AND b.phone != ''
              ))"""

def _legacy_kothi_where() -> str:
    return "(k.is_deleted != 1 OR k.is_deleted IS NULL)"

def _legacy_search_clause(search: Optional[str], source: str) -> tuple[str, List[str]]:
    query = (search or "").strip()
    if not query:
        return "", []

    like = f"%{query}%"
    digits = re.sub(r"[^0-9]", "", query)
    phone_key = digits[-10:] if len(digits) >= 10 else digits

    if source == "kothi":
        clauses = [
            "k.location LIKE %s",
            "k.address LIKE %s",
            "k.owner_name LIKE %s",
            "k.details LIKE %s",
            "k.plot_size LIKE %s",
            "k.floor LIKE %s",
            "k.accommodation LIKE %s",
        ]
        params = [like, like, like, like, like, like, like]
        if phone_key:
            clauses.append("REGEXP_REPLACE(COALESCE(NULLIF(k.contact, ''), CONCAT_WS('', k.contact_1, k.contact_2), ''), '[^0-9]', '') LIKE %s")
            params.append(f"%{phone_key}%")
        return f" AND ({' OR '.join(clauses)})", params

    clauses = [
        "e.name LIKE %s",
        "e.location LIKE %s",
        "e.address LIKE %s",
        "e.notes LIKE %s",
        "e.flat_type LIKE %s",
        "e.bhk LIKE %s",
        "e.floor LIKE %s",
    ]
    params = [like, like, like, like, like, like, like]
    if phone_key:
        clauses.append("REGEXP_REPLACE(e.phone, '[^0-9]', '') LIKE %s")
        params.append(f"%{phone_key}%")
    return f" AND ({' OR '.join(clauses)})", params

def _legacy_search_criteria_clause(
    source: str,
    name: Optional[str] = None,
    location: Optional[str] = None,
    address: Optional[str] = None,
    phone: Optional[str] = None,
    status: Optional[str] = None,
    message_status: Optional[str] = None,
) -> tuple[str, List[str]]:
    clauses: List[str] = []
    params: List[str] = []

    field_columns = {
        "kothi": {
            "name": "k.owner_name",
            "location": "k.location",
            "address": "k.address",
        },
        "floor": {
            "name": "e.name",
            "location": "e.location",
            "address": "e.address",
        },
    }[source]

    for value, column in (
        (name, field_columns["name"]),
        (location, field_columns["location"]),
        (address, field_columns["address"]),
    ):
        query = (value or "").strip()
        if query:
            clauses.append(f"{column} LIKE %s")
            params.append(f"%{query}%")

    phone_digits = re.sub(r"[^0-9]", "", phone or "")
    if phone_digits:
        phone_key = phone_digits[-10:] if len(phone_digits) >= 10 else phone_digits
        if source == "kothi":
            phone_expression = "REGEXP_REPLACE(COALESCE(NULLIF(k.contact, ''), CONCAT_WS('', k.contact_1, k.contact_2), ''), '[^0-9]', '')"
        else:
            phone_expression = "REGEXP_REPLACE(COALESCE(e.phone, ''), '[^0-9]', '')"
        clauses.append(f"{phone_expression} LIKE %s")
        params.append(f"%{phone_key}%")

    status_query = (status or "").strip()
    if status_query:
        status_column = "k.status" if source == "kothi" else "e.status"
        clauses.append(f"{status_column} LIKE %s")
        params.append(f"%{status_query}%")

    if message_status == "not_sent":
        sent_column = "k.last_message_sent_on" if source == "kothi" else "e.last_message_sent_on"
        clauses.append(f"{sent_column} IS NULL")
    elif message_status == "sent":
        sent_column = "k.last_message_sent_on" if source == "kothi" else "e.last_message_sent_on"
        clauses.append(f"{sent_column} IS NOT NULL")

    if not clauses:
        return "", []
    return f" AND {' AND '.join(clauses)}", params

def _legacy_floor_select() -> str:
    return """
        SELECT
            e.id,
            e.name,
            e.phone,
            e.location,
            e.address,
            e.flat_type,
            e.bhk,
            e.floor,
            e.budget_min,
            e.budget_max,
            e.unit,
            e.area_size,
            e.property_type,
            e.status,
            e.notes,
            e.created_at,
            e.last_message_sent_on,
            'floor' as legacy_category,
            'enquiries' as legacy_source
        FROM enquiries e
    """

def _legacy_kothi_select() -> str:
    return """
        SELECT
            k.id,
            COALESCE(NULLIF(k.owner_name, ''), NULLIF(CONCAT_WS(' ', k.location, k.address, k.plot_size, k.floor, k.rental), ''), CONCAT('Kothi #', k.id)) as name,
            COALESCE(NULLIF(k.contact, ''), NULLIF(CONCAT_WS(', ', k.contact_1, k.contact_2), '')) as phone,
            k.location,
            k.address,
            NULL as flat_type,
            k.accommodation as bhk,
            k.floor,
            NULL as budget_min,
            NULL as budget_max,
            'CR' as unit,
            k.plot_size as area_size,
            'Kothi' as property_type,
            k.status,
            TRIM(CONCAT_WS(' ', k.details, k.rental)) as notes,
            k.created_at,
            k.last_message_sent_on,
            'kothi' as legacy_category,
            'kothis_details' as legacy_source
        FROM kothis_details k
    """

def _normalize_legacy_inventory_rows(rows: List[dict], user_role: str, user_id: int) -> List[dict]:
    result = []
    for row in rows:
        item = dict(row)
        if item.get("created_at"):
            item["created_at"] = item["created_at"].isoformat()
        if item.get("last_message_sent_on"):
            item["last_message_sent_on"] = item["last_message_sent_on"].isoformat()
        can_view_sensitive = not should_mask_data(user_role, user_id, None)
        item["can_view_sensitive"] = can_view_sensitive
        if not can_view_sensitive:
            if item.get("phone"):
                item["phone"] = mask_phone(str(item["phone"]))
            if item.get("address"):
                item["address"] = mask_address(str(item["address"]))
        result.append(item)
    return result

@api_router.get("/mobile/workbench")
def get_mobile_workbench(current_user: dict = Depends(get_current_user)):
    """Mobile-first daily workbench: priority tasks, fresh leads, hot leads, and smart matches."""
    user_role = current_user.get('role', '')
    user_id = current_user.get('id')
    today = datetime.utcnow().date()

    def normalize_action_rows(rows):
        normalized = []
        assignment_map = current_assignee_map(
            cursor,
            [row.get('lead_id') for row in rows if row.get('lead_id')]
        )
        for row in rows:
            item = dict(row)
            item['lead_current_assignee_id'] = (
                assignment_map.get(int(item['lead_id'])) if item.get('lead_id') else None
            )
            item['can_view_sensitive'] = not should_mask_data(
                user_role,
                user_id,
                item.get('lead_created_by'),
                item.get('lead_current_assignee_id'),
            )
            if not item['can_view_sensitive']:
                item['lead_phone'] = mask_phone(item.get('lead_phone'))
            item['due_date'] = str(item['due_date']) if item.get('due_date') else None
            item['due_time'] = str(item['due_time']) if item.get('due_time') else None
            normalized.append(item)
        return normalized

    with get_db() as conn:
        cursor = conn.cursor()
        ensure_action_assignment_column(cursor)
        ensure_whatsapp_tracking_columns(cursor)
        ensure_whatsapp_logs_table(cursor)
        conn.commit()

        action_select = """
            SELECT a.id, a.lead_id, a.title, a.description, a.action_type, a.due_date, a.due_time,
                   a.status, a.priority, l.name as lead_name, l.phone as lead_phone, l.lead_type,
                   l.created_by as lead_created_by, u.full_name as assigned_to_name
            FROM actions a
            LEFT JOIN leads l ON l.id = a.lead_id
            LEFT JOIN users u ON u.id = a.assigned_to
            WHERE a.status IN ('Pending', 'Up Coming', 'Missed')
              AND (a.user_id = %s OR a.assigned_to = %s OR %s = 'admin')
              AND LOWER(IFNULL(l.lead_type, '')) IN ('buyer', 'tenant')
              AND (l.is_deleted IS NULL OR l.is_deleted = 0)
        """

        cursor.execute(f"""
            {action_select}
              AND a.due_date < %s
            ORDER BY a.due_date ASC, a.due_time ASC
            LIMIT 20
        """, (user_id, user_id, user_role, today))
        missed_actions = normalize_action_rows(cursor.fetchall())

        cursor.execute(f"""
            {action_select}
              AND (a.due_date = %s OR a.due_date IS NULL)
            ORDER BY CASE WHEN a.due_date IS NULL THEN 1 ELSE 0 END, a.due_time ASC
            LIMIT 20
        """, (user_id, user_id, user_role, today))
        today_actions = normalize_action_rows(cursor.fetchall())

        cursor.execute(f"""
            {action_select}
              AND (a.due_date <= %s OR a.due_date IS NULL)
            ORDER BY
              CASE WHEN a.due_date < %s THEN 0 WHEN a.due_date = %s THEN 1 ELSE 2 END,
              a.due_date ASC, a.due_time ASC
            LIMIT 20
        """, (user_id, user_id, user_role, today, today, today))
        actions = normalize_action_rows(cursor.fetchall())

        cursor.execute("""
            SELECT l.*, u.full_name as created_by_name, NULL as assigned_to_name
            FROM leads l
            LEFT JOIN users u ON u.id = l.created_by
            WHERE l.lead_type IN ('buyer', 'tenant')
              AND (l.is_deleted IS NULL OR l.is_deleted = 0)
              AND COALESCE(l.lead_temperature, '') = 'Hot'
              AND NOT EXISTS (
                SELECT 1 FROM actions a
                WHERE a.lead_id = l.id AND a.status IN ('Pending', 'Up Coming')
              )
            ORDER BY l.created_at DESC
            LIMIT 10
        """)
        hot_rows = cursor.fetchall()
        attach_current_assignees(cursor, hot_rows)
        hot_leads = [_lead_summary(row, user_role, user_id) for row in hot_rows]

        cursor.execute("""
            SELECT l.*, u.full_name as created_by_name, NULL as assigned_to_name
            FROM leads l
            LEFT JOIN users u ON u.id = l.created_by
            WHERE l.lead_type IN ('buyer', 'tenant')
              AND (l.is_deleted IS NULL OR l.is_deleted = 0)
              AND (l.notes IS NULL OR TRIM(l.notes) = '')
            ORDER BY l.created_at DESC
            LIMIT 10
        """)
        notes_rows = cursor.fetchall()
        attach_current_assignees(cursor, notes_rows)
        notes_missing = [_lead_summary(row, user_role, user_id) for row in notes_rows]

        cursor.execute("""
            SELECT l.*, u.full_name as created_by_name, NULL as assigned_to_name,
                   DATEDIFF(CURDATE(), DATE(l.last_message_sent_on)) as days_since_whatsapp,
                   (
                     SELECT COUNT(*)
                     FROM whatsapp_logs wl
                     WHERE wl.lead_id = l.id
                   ) as whatsapp_log_count,
                   (
                     SELECT COUNT(*)
                     FROM actions a
                     WHERE a.lead_id = l.id
                       AND a.status IN ('Pending', 'Up Coming', 'Missed')
                   ) as pending_action_count
            FROM leads l
            LEFT JOIN users u ON u.id = l.created_by
            WHERE LOWER(IFNULL(l.lead_type, '')) IN ('buyer', 'tenant')
              AND (l.is_deleted IS NULL OR l.is_deleted = 0)
              AND (l.lead_status IS NULL OR l.lead_status NOT IN ('Won', 'Closed/Lost', 'Lost', 'Sold', 'Already Rented'))
              AND (l.last_message_sent_on IS NULL OR DATE(l.last_message_sent_on) <= DATE_SUB(CURDATE(), INTERVAL 3 DAY))
            ORDER BY l.last_message_sent_on IS NULL DESC, l.last_message_sent_on ASC, l.created_at DESC
            LIMIT 15
        """)
        whatsapp_due = []
        whatsapp_rows = cursor.fetchall()
        attach_current_assignees(cursor, whatsapp_rows)
        for row in whatsapp_rows:
            item = _lead_summary(row, user_role, user_id)
            item["last_message_sent_on"] = row.get("last_message_sent_on").isoformat() if row.get("last_message_sent_on") else None
            item["days_since_whatsapp"] = row.get("days_since_whatsapp")
            item.update(_build_whatsapp_intelligence(row))
            whatsapp_due.append(item)

    smart_match_inbox = get_smart_matches(current_user=current_user, limit=12)

    return {
        "date": today.isoformat(),
        "priority_actions": actions,
        "missed_actions": missed_actions,
        "today_actions": today_actions,
        "whatsapp_due_leads": whatsapp_due,
        "hot_leads_without_action": hot_leads,
        "notes_missing": notes_missing,
        "smart_matches": smart_match_inbox,
        "summary": {
            "priority_actions": len(actions),
            "missed_actions": len(missed_actions),
            "today_actions": len(today_actions),
            "whatsapp_due_leads": len(whatsapp_due),
            "hot_leads_without_action": len(hot_leads),
            "notes_missing": len(notes_missing),
            "smart_matches": len(smart_match_inbox),
        }
    }

@api_router.get("/mobile/assigned-leads")
def get_mobile_assigned_leads(current_user: dict = Depends(get_current_user), limit: int = 100):
    """Leads assigned to the current user, with admin able to see all assigned leads."""
    user_role = current_user.get('role', '')
    user_id = current_user.get('id')
    safe_limit = max(1, min(limit, 500))
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        conn.commit()
        assignment_columns = _table_columns(cursor, 'lead_assignments')
        assignment_order = "la.assigned_at DESC"
        if 'id' in assignment_columns:
            assignment_order += ", la.id DESC"
        where = (
            "(l.assigned_to IS NOT NULL OR EXISTS (SELECT 1 FROM lead_assignments la WHERE la.lead_id = l.id))"
            if user_role == 'admin'
            else """(
                l.assigned_to = %s OR EXISTS (
                    SELECT 1 FROM lead_assignments la
                    WHERE la.lead_id = l.id AND la.user_id = %s
                )
            )"""
        )
        params: List[Any] = [] if user_role == 'admin' else [user_id]
        if user_role != 'admin':
            params.append(user_id)
        params.append(safe_limit)
        cursor.execute(f"""
            SELECT l.*, u.full_name as created_by_name,
                   COALESCE(latest_assignee.full_name, assignee.full_name) as assigned_to_name
            FROM leads l
            LEFT JOIN users u ON u.id = l.created_by
            LEFT JOIN users assignee ON assignee.id = l.assigned_to
            LEFT JOIN users latest_assignee ON latest_assignee.id = (
                SELECT la.user_id FROM lead_assignments la
                WHERE la.lead_id = l.id
                ORDER BY {assignment_order}
                LIMIT 1
            )
            WHERE {where}
              AND (l.is_deleted IS NULL OR l.is_deleted = 0)
            ORDER BY l.created_at DESC
            LIMIT %s
        """, params)
        rows = cursor.fetchall()
        attach_current_assignees(cursor, rows)
        return [_lead_summary(row, user_role, user_id) for row in rows]

@api_router.get("/mobile/enquiries")
def get_mobile_enquiries(
    current_user: dict = Depends(get_current_user),
    limit: int = 100,
    category: Optional[str] = None,
    search: Optional[str] = None,
    name: Optional[str] = None,
    location: Optional[str] = None,
    address: Optional[str] = None,
    phone: Optional[str] = None,
    status: Optional[str] = None,
    message_status: Optional[str] = None,
):
    """Legacy inventory records using the same sources as kothis.php and legacy_leads.php."""
    safe_limit = max(1, min(limit, 300))
    safe_category = category if category in ("kothi", "floor") else "all"
    user_role = current_user.get('role', '')
    user_id = current_user.get('id')
    with get_db() as conn:
        cursor = conn.cursor()
        if not _table_exists(cursor, "kothis_details") and not _table_exists(cursor, "enquiries"):
            return {"items": [], "table": None, "message": "No legacy inventory tables found"}

        kothi_where = _legacy_kothi_where()
        floor_where = _legacy_floor_where()
        kothi_search_clause, kothi_search_params = _legacy_search_clause(search, "kothi")
        floor_search_clause, floor_search_params = _legacy_search_clause(search, "floor")
        kothi_criteria_clause, kothi_criteria_params = _legacy_search_criteria_clause(
            "kothi", name, location, address, phone, status, message_status
        )
        floor_criteria_clause, floor_criteria_params = _legacy_search_criteria_clause(
            "floor", name, location, address, phone, status, message_status
        )
        kothi_search_clause += kothi_criteria_clause
        floor_search_clause += floor_criteria_clause
        kothi_search_params += kothi_criteria_params
        floor_search_params += floor_criteria_params

        cursor.execute("SELECT COUNT(*) as count FROM kothis_details")
        kothi_historical = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) as count FROM enquiries")
        floor_historical = cursor.fetchone()["count"]

        cursor.execute(f"SELECT COUNT(*) as count FROM kothis_details k WHERE {kothi_where}{kothi_search_clause}", tuple(kothi_search_params))
        kothi_count = cursor.fetchone()["count"]
        cursor.execute(f"SELECT COUNT(*) as count FROM enquiries e WHERE {floor_where}{floor_search_clause}", tuple(floor_search_params))
        floor_count = cursor.fetchone()["count"]

        rows = []
        if safe_category == "kothi":
            cursor.execute(
                f"{_legacy_kothi_select()} WHERE {kothi_where}{kothi_search_clause} ORDER BY k.id DESC LIMIT %s",
                tuple(kothi_search_params + [safe_limit])
            )
            rows = cursor.fetchall()
        elif safe_category == "floor":
            cursor.execute(
                f"{_legacy_floor_select()} WHERE {floor_where}{floor_search_clause} ORDER BY e.created_at DESC LIMIT %s",
                tuple(floor_search_params + [safe_limit])
            )
            rows = cursor.fetchall()
        else:
            kothi_limit = max(1, safe_limit // 2)
            floor_limit = safe_limit - kothi_limit
            cursor.execute(
                f"{_legacy_kothi_select()} WHERE {kothi_where}{kothi_search_clause} ORDER BY k.id DESC LIMIT %s",
                tuple(kothi_search_params + [kothi_limit])
            )
            rows.extend(cursor.fetchall())
            cursor.execute(
                f"{_legacy_floor_select()} WHERE {floor_where}{floor_search_clause} ORDER BY e.created_at DESC LIMIT %s",
                tuple(floor_search_params + [floor_limit])
            )
            rows.extend(cursor.fetchall())
            rows.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)

        return {
            "items": _normalize_legacy_inventory_rows(rows, user_role, user_id),
            "table": "kothis_details,enquiries",
            "category": safe_category,
            "search": search or "",
            "criteria": {
                "name": name or "",
                "location": location or "",
                "address": address or "",
                "phone": phone or "",
                "status": status or "",
                "message_status": message_status or "all",
            },
            "total": kothi_count + floor_count,
            "historical_total": kothi_historical + floor_historical,
            "counts": {
                "all": kothi_count + floor_count,
                "kothi": kothi_count,
                "floor": floor_count,
            }
        }

class LegacyInventoryStatusUpdate(BaseModel):
    status: str

@api_router.put("/mobile/legacy-inventory/{source}/{legacy_id}/status")
def update_mobile_legacy_inventory_status(
    source: str,
    legacy_id: int,
    payload: LegacyInventoryStatusUpdate,
    current_user: dict = Depends(get_current_user),
):
    """Update a Kothi or floor legacy record using the Web LMS status set."""
    table = {"enquiries": "enquiries", "kothis_details": "kothis_details"}.get(source)
    status = (payload.status or "").strip()
    allowed_statuses = {
        "Potential", "Contacted", "Pending", "Converted",
        "Not Interested", "Invalid Number", "Sold", "Not Picking Call",
    }
    if not table:
        raise HTTPException(status_code=400, detail="Unsupported legacy inventory source")
    if status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Invalid legacy inventory status")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"UPDATE {table} SET status = %s WHERE id = %s AND (is_deleted IS NULL OR is_deleted != 1)",
            (status, legacy_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Legacy inventory record not found")
        conn.commit()
    return {"message": "Legacy status updated", "id": legacy_id, "source": source, "status": status}

@api_router.delete("/mobile/legacy-inventory/{source}/{legacy_id}")
def delete_mobile_legacy_inventory(
    source: str,
    legacy_id: int,
    current_user: dict = Depends(get_current_user),
):
    """Soft-delete a legacy inventory record."""
    table = {"enquiries": "enquiries", "kothis_details": "kothis_details"}.get(source)
    if not table:
        raise HTTPException(status_code=400, detail="Unsupported legacy inventory source")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"UPDATE {table} SET is_deleted = 1 WHERE id = %s AND (is_deleted IS NULL OR is_deleted != 1)",
            (legacy_id,),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Legacy inventory record not found")
        conn.commit()
    return {"message": "Legacy inventory deleted", "id": legacy_id, "source": source}

@api_router.post("/mobile/enquiries/{enquiry_id}/convert")
def convert_mobile_enquiry(enquiry_id: int, current_user: dict = Depends(get_current_user)):
    """Convert an advertised enquiry into a buyer lead when the enquiry table is available."""
    with get_db() as conn:
        cursor = conn.cursor()
        meta = _find_enquiry_table(cursor)
        if not meta:
            raise HTTPException(status_code=404, detail="No enquiry table found")

        table = meta["table"]
        select_parts = _enquiry_select_parts(meta)

        cursor.execute(f"SELECT {', '.join(select_parts)} FROM {table} WHERE {meta['id']} = %s LIMIT 1", (enquiry_id,))
        enquiry = cursor.fetchone()
        if not enquiry:
            raise HTTPException(status_code=404, detail="Enquiry not found")

        cursor.execute("""
            INSERT INTO leads (name, phone, lead_type, location, lead_temperature, lead_status, lead_source, notes, created_by, created_at)
            VALUES (%s, %s, 'buyer', %s, 'Hot', 'New', %s, %s, %s, NOW())
        """, (
            enquiry.get("name") or "Advertised enquiry",
            enquiry.get("phone"),
            enquiry.get("location"),
            enquiry.get("source") or "Advertisement",
            enquiry.get("notes"),
            current_user['id'],
        ))
        lead_id = cursor.lastrowid
        converted_col = meta.get("converted")
        if converted_col:
            try:
                cursor.execute(f"UPDATE {table} SET {converted_col} = 1 WHERE {meta['id']} = %s", (enquiry_id,))
            except Exception as exc:
                logging.warning(f"Could not mark enquiry converted: {exc}")
        conn.commit()
        return {"message": "Enquiry converted", "lead_id": lead_id}

# ============= Mobile Collaboration & Performance =============
@api_router.get("/collaboration/inbox")
def get_collaboration_inbox(limit: int = 80, current_user: dict = Depends(get_current_user)):
    safe_limit = max(1, min(limit, 100))
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        conn.commit()
        cursor.execute("""
            SELECT n.*, l.name AS lead_name,
                   CASE
                     WHEN n.notification_type = 'handoff' THEN (
                       SELECT h.status FROM lead_handoffs h WHERE h.id = n.reference_id
                     )
                     ELSE NULL
                   END AS handoff_status
            FROM collaboration_notifications n
            LEFT JOIN leads l ON l.id = n.lead_id
            WHERE n.user_id = %s
            ORDER BY n.is_read ASC, n.created_at DESC, n.id DESC
            LIMIT %s
        """, (current_user['id'], safe_limit))
        rows = [dict(row) for row in cursor.fetchall()]
        unread = sum(1 for row in rows if not row.get('is_read'))
        return {"unread": unread, "items": rows}

@api_router.put("/collaboration/inbox/read")
def mark_collaboration_inbox_read(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        cursor.execute("""
            UPDATE collaboration_notifications
            SET is_read = 1, read_at = NOW()
            WHERE user_id = %s AND is_read = 0
        """, (current_user['id'],))
        conn.commit()
        return {"message": "Team inbox marked read"}

@api_router.get("/leads/{lead_id}/collaboration")
def get_lead_collaboration(lead_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        conn.commit()
        if not can_access_collaboration_lead(cursor, lead_id, current_user):
            raise HTTPException(status_code=403, detail="You do not have access to this lead")

        cursor.execute("""
            SELECT c.id, c.lead_id, c.user_id, c.body, c.created_at,
                   u.full_name AS author_name
            FROM lead_comments c
            LEFT JOIN users u ON u.id = c.user_id
            WHERE c.lead_id = %s
            ORDER BY c.created_at DESC, c.id DESC
            LIMIT 50
        """, (lead_id,))
        comments = [dict(row) for row in cursor.fetchall()]
        if comments:
            comment_ids = [row['id'] for row in comments]
            placeholders = ','.join(['%s'] * len(comment_ids))
            cursor.execute(f"""
                SELECT m.comment_id, m.user_id, u.full_name
                FROM lead_comment_mentions m
                JOIN users u ON u.id = m.user_id
                WHERE m.comment_id IN ({placeholders})
                ORDER BY u.full_name
            """, comment_ids)
            mention_map: Dict[int, List[dict]] = {}
            for row in cursor.fetchall():
                mention_map.setdefault(row['comment_id'], []).append(dict(row))
            for comment in comments:
                comment['mentions'] = mention_map.get(comment['id'], [])

        cursor.execute("""
            SELECT h.*, from_user.full_name AS from_user_name,
                   to_user.full_name AS to_user_name,
                   initiator.full_name AS initiated_by_name
            FROM lead_handoffs h
            LEFT JOIN users from_user ON from_user.id = h.from_user_id
            LEFT JOIN users to_user ON to_user.id = h.to_user_id
            LEFT JOIN users initiator ON initiator.id = h.initiated_by
            WHERE h.lead_id = %s
            ORDER BY h.created_at DESC, h.id DESC
            LIMIT 20
        """, (lead_id,))
        handoffs = [dict(row) for row in cursor.fetchall()]

        cursor.execute("""
            SELECT id, username, full_name, role
            FROM users
            WHERE LOWER(TRIM(role)) IN ('admin','manager','user','caller','tele caller','telecaller')
            ORDER BY COALESCE(NULLIF(full_name, ''), username)
        """)
        users = [dict(row) for row in cursor.fetchall()]

        cursor.execute("""
            SELECT COALESCE(
                (
                    SELECT la.user_id
                    FROM lead_assignments la
                    WHERE la.lead_id = l.id
                    ORDER BY la.assigned_at DESC
                    LIMIT 1
                ),
                NULLIF(l.assigned_to, 0),
                l.created_by
            ) AS user_id
            FROM leads l
            WHERE l.id = %s
        """, (lead_id,))
        owner_row = cursor.fetchone() or {}
        owner_id = owner_row.get('user_id')
        owner = next((user for user in users if user.get('id') == owner_id), None)

        cursor.execute("""
            UPDATE collaboration_notifications
            SET is_read = 1, read_at = NOW()
            WHERE lead_id = %s AND user_id = %s AND is_read = 0
        """, (lead_id, current_user['id']))
        cursor.execute("""
            UPDATE lead_comment_mentions m
            JOIN lead_comments c ON c.id = m.comment_id
            SET m.is_read = 1, m.read_at = NOW()
            WHERE c.lead_id = %s AND m.user_id = %s AND m.is_read = 0
        """, (lead_id, current_user['id']))
        conn.commit()

        return {
            "comments": comments,
            "handoffs": handoffs,
            "users": users,
            "owner": owner,
            "current_user_id": current_user['id'],
        }

@api_router.post("/leads/{lead_id}/collaboration/comments")
def add_lead_comment(
    lead_id: int,
    payload: CollaborationCommentCreate,
    current_user: dict = Depends(get_current_user),
):
    body = payload.body.strip()
    if not body:
        raise HTTPException(status_code=400, detail="Comment text is required")
    if len(body) > 5000:
        raise HTTPException(status_code=400, detail="Comment is too long")
    mention_ids = sorted({
        int(user_id) for user_id in (payload.mention_ids or [])
        if int(user_id) > 0 and int(user_id) != current_user['id']
    })

    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        if not can_access_collaboration_lead(cursor, lead_id, current_user):
            raise HTTPException(status_code=403, detail="You do not have access to this lead")
        if mention_ids:
            placeholders = ','.join(['%s'] * len(mention_ids))
            cursor.execute(f"""
                SELECT id FROM users
                WHERE id IN ({placeholders})
                  AND LOWER(TRIM(role)) IN ('admin','manager','user','caller','tele caller','telecaller')
            """, mention_ids)
            mention_ids = [row['id'] for row in cursor.fetchall()]

        try:
            cursor.execute(
                "INSERT INTO lead_comments (lead_id, user_id, body) VALUES (%s, %s, %s)",
                (lead_id, current_user['id'], body),
            )
            comment_id = cursor.lastrowid
            author = current_user.get('full_name') or current_user.get('username') or 'A teammate'
            for mentioned_user_id in mention_ids:
                cursor.execute("""
                    INSERT INTO lead_collaborators (lead_id, user_id, added_by, source)
                    VALUES (%s, %s, %s, 'mention')
                    ON DUPLICATE KEY UPDATE added_by = VALUES(added_by)
                """, (lead_id, mentioned_user_id, current_user['id']))
                cursor.execute("""
                    INSERT IGNORE INTO lead_comment_mentions (comment_id, user_id)
                    VALUES (%s, %s)
                """, (comment_id, mentioned_user_id))
                cursor.execute("""
                    INSERT INTO collaboration_notifications
                        (user_id, lead_id, notification_type, reference_id, message)
                    VALUES (%s, %s, 'mention', %s, %s)
                """, (
                    mentioned_user_id,
                    lead_id,
                    comment_id,
                    f"{author} mentioned you in a lead comment.",
                ))
            conn.commit()
            return {"message": "Comment added", "comment_id": comment_id}
        except Exception:
            conn.rollback()
            raise

@api_router.post("/leads/{lead_id}/collaboration/handoffs")
def request_lead_handoff(
    lead_id: int,
    payload: CollaborationHandoffCreate,
    current_user: dict = Depends(get_current_user),
):
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        if not can_access_collaboration_lead(cursor, lead_id, current_user):
            raise HTTPException(status_code=403, detail="You do not have access to this lead")

        cursor.execute("""
            SELECT COALESCE(
                (
                    SELECT la.user_id FROM lead_assignments la
                    WHERE la.lead_id = l.id ORDER BY la.assigned_at DESC LIMIT 1
                ),
                NULLIF(l.assigned_to, 0),
                l.created_by
            ) AS owner_id
            FROM leads l WHERE l.id = %s
        """, (lead_id,))
        owner_id = (cursor.fetchone() or {}).get('owner_id')
        role = str(current_user.get('role') or '').lower()
        if current_user['id'] != owner_id and role not in {'admin', 'manager'}:
            raise HTTPException(status_code=403, detail="Only the current owner or manager can request a handoff")
        if payload.to_user_id == owner_id:
            raise HTTPException(status_code=400, detail="Choose a different teammate")

        cursor.execute("SELECT id, full_name FROM users WHERE id = %s", (payload.to_user_id,))
        recipient = cursor.fetchone()
        if not recipient:
            raise HTTPException(status_code=404, detail="Selected teammate was not found")
        cursor.execute("""
            SELECT id FROM lead_handoffs
            WHERE lead_id = %s AND to_user_id = %s AND status = 'pending'
        """, (lead_id, payload.to_user_id))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="A handoff to this teammate is already pending")

        cursor.execute("""
            INSERT INTO lead_handoffs
                (lead_id, from_user_id, to_user_id, initiated_by, note, status)
            VALUES (%s, %s, %s, %s, %s, 'pending')
        """, (
            lead_id,
            owner_id,
            payload.to_user_id,
            current_user['id'],
            (payload.note or '').strip(),
        ))
        handoff_id = cursor.lastrowid
        initiator = current_user.get('full_name') or current_user.get('username') or 'A teammate'
        cursor.execute("""
            INSERT INTO collaboration_notifications
                (user_id, lead_id, notification_type, reference_id, message)
            VALUES (%s, %s, 'handoff', %s, %s)
        """, (
            payload.to_user_id,
            lead_id,
            handoff_id,
            f"{initiator} requested a lead handoff to you.",
        ))
        conn.commit()
        return {"message": "Handoff request sent", "handoff_id": handoff_id}

@api_router.put("/collaboration/handoffs/{handoff_id}")
def respond_to_lead_handoff(
    handoff_id: int,
    payload: CollaborationHandoffResponse,
    current_user: dict = Depends(get_current_user),
):
    decision = payload.decision.strip().lower()
    if decision not in {'accepted', 'declined'}:
        raise HTTPException(status_code=400, detail="Decision must be accepted or declined")

    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        ensure_action_assignment_column(cursor)
        conn.begin()
        try:
            cursor.execute("""
                SELECT * FROM lead_handoffs
                WHERE id = %s AND to_user_id = %s AND status = 'pending'
                FOR UPDATE
            """, (handoff_id, current_user['id']))
            handoff = cursor.fetchone()
            if not handoff:
                raise HTTPException(status_code=404, detail="Handoff is no longer pending")
            cursor.execute("""
                UPDATE lead_handoffs SET status = %s, responded_at = NOW() WHERE id = %s
            """, (decision, handoff_id))

            if decision == 'accepted':
                lead_id = handoff['lead_id']
                cursor.execute("DELETE FROM lead_assignments WHERE lead_id = %s", (lead_id,))
                cursor.execute("""
                    INSERT INTO lead_assignments (lead_id, user_id, assigned_by)
                    VALUES (%s, %s, %s)
                """, (lead_id, current_user['id'], handoff['initiated_by']))
                cursor.execute("""
                    UPDATE leads SET assigned_to = %s WHERE id = %s
                """, (current_user['id'], lead_id))
                cursor.execute("""
                    UPDATE actions
                    SET user_id = %s, assigned_to = %s
                    WHERE lead_id = %s AND status IN ('Pending','Missed','Up Coming')
                """, (current_user['id'], current_user['id'], lead_id))

            responder = current_user.get('full_name') or current_user.get('username') or 'The recipient'
            notify_ids = {
                int(handoff.get('initiated_by') or 0),
                int(handoff.get('from_user_id') or 0),
            }
            for notify_user_id in notify_ids:
                if notify_user_id <= 0 or notify_user_id == current_user['id']:
                    continue
                cursor.execute("""
                    INSERT INTO collaboration_notifications
                        (user_id, lead_id, notification_type, reference_id, message)
                    VALUES (%s, %s, 'handoff_response', %s, %s)
                """, (
                    notify_user_id,
                    handoff['lead_id'],
                    handoff_id,
                    f"{responder} {decision} the lead handoff.",
                ))
            cursor.execute("""
                UPDATE collaboration_notifications
                SET is_read = 1, read_at = NOW()
                WHERE user_id = %s AND notification_type = 'handoff' AND reference_id = %s
            """, (current_user['id'], handoff_id))
            conn.commit()
            return {"message": f"Handoff {decision}", "lead_id": handoff['lead_id']}
        except HTTPException:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise

@api_router.get("/mobile/performance")
def get_mobile_performance(
    days: int = 30,
    agent_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user),
):
    safe_days = max(7, min(days, 90))
    role = str(current_user.get('role') or '').strip().lower()
    selected_agent_id = agent_id if role in {'admin', 'manager'} and agent_id else current_user['id']
    from_date = datetime.utcnow().date() - timedelta(days=safe_days - 1)
    today = datetime.utcnow().date()

    with get_db() as conn:
        cursor = conn.cursor()
        ensure_action_assignment_column(cursor)
        ensure_collaboration_tables(cursor)
        conn.commit()

        cursor.execute("""
            SELECT id, username, full_name, role
            FROM users WHERE id = %s
        """, (selected_agent_id,))
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Team member not found")

        owner_expr = "COALESCE(NULLIF(a.assigned_to, 0), a.user_id)"
        cursor.execute(f"""
            SELECT
              COUNT(*) AS actions_due,
              SUM(a.status = 'Completed') AS actions_completed,
              SUM(
                a.status = 'Completed'
                AND a.completed_at IS NOT NULL
                AND a.completed_at <= CONCAT(a.due_date, ' ', COALESCE(a.due_time, '23:59:59'))
              ) AS completed_on_time,
              SUM(
                a.status IN ('Pending','Missed','Up Coming')
                AND CONCAT(a.due_date, ' ', COALESCE(a.due_time, '23:59:59')) < NOW()
              ) AS overdue_actions
            FROM actions a
            WHERE {owner_expr} = %s AND a.due_date BETWEEN %s AND %s
        """, (selected_agent_id, from_date, today))
        action_stats = dict(cursor.fetchone() or {})

        cursor.execute("""
            SELECT COUNT(DISTINCT l.id) AS open_portfolio
            FROM leads l
            WHERE (l.is_deleted IS NULL OR l.is_deleted = 0)
              AND LOWER(IFNULL(l.lead_status,'')) NOT IN ('sold','closed','closed/lost','closed/lost','already rented')
              AND (
                  l.created_by = %s OR l.assigned_to = %s OR EXISTS (
                      SELECT 1 FROM lead_assignments la
                      WHERE la.lead_id = l.id AND la.user_id = %s
                  )
              )
        """, (selected_agent_id, selected_agent_id, selected_agent_id))
        open_portfolio = int((cursor.fetchone() or {}).get('open_portfolio') or 0)

        cursor.execute("""
            SELECT COUNT(*) AS leads_created,
                   SUM(lead_status = 'Won') AS won_leads
            FROM leads
            WHERE created_by = %s
              AND (is_deleted IS NULL OR is_deleted = 0)
              AND DATE(created_at) BETWEEN %s AND %s
        """, (selected_agent_id, from_date, today))
        lead_stats = dict(cursor.fetchone() or {})

        visits = 0
        if _table_exists(cursor, 'site_visits'):
            visit_columns = _table_columns(cursor, 'site_visits')
            owner_column = 'created_by' if 'created_by' in visit_columns else None
            date_column = 'visit_date' if 'visit_date' in visit_columns else 'created_at'
            if owner_column:
                cursor.execute(f"""
                    SELECT COUNT(*) AS total FROM site_visits
                    WHERE {owner_column} = %s AND DATE({date_column}) BETWEEN %s AND %s
                """, (selected_agent_id, from_date, today))
                visits = int((cursor.fetchone() or {}).get('total') or 0)

        due = int(action_stats.get('actions_due') or 0)
        completed = int(action_stats.get('actions_completed') or 0)
        on_time = int(action_stats.get('completed_on_time') or 0)
        overdue = int(action_stats.get('overdue_actions') or 0)
        summary = {
            "actions_due": due,
            "actions_completed": completed,
            "completed_on_time": on_time,
            "overdue_actions": overdue,
            "completion_rate": round((completed / due) * 100, 1) if due else 0,
            "on_time_rate": round((on_time / completed) * 100, 1) if completed else 0,
            "open_portfolio": open_portfolio,
            "leads_created": int(lead_stats.get('leads_created') or 0),
            "won_leads": int(lead_stats.get('won_leads') or 0),
            "site_visits": visits,
        }

        cursor.execute(f"""
            SELECT a.id, a.lead_id, a.title, a.action_type, a.due_date, a.due_time,
                   l.name AS lead_name,
                   TIMESTAMPDIFF(
                     HOUR,
                     CONCAT(a.due_date, ' ', COALESCE(a.due_time, '23:59:59')),
                     NOW()
                   ) AS hours_overdue
            FROM actions a
            LEFT JOIN leads l ON l.id = a.lead_id
            WHERE {owner_expr} = %s
              AND a.status IN ('Pending','Missed','Up Coming')
              AND CONCAT(a.due_date, ' ', COALESCE(a.due_time, '23:59:59')) < NOW()
            ORDER BY hours_overdue DESC
            LIMIT 10
        """, (selected_agent_id,))
        overdue_items = [dict(row) for row in cursor.fetchall()]

        available_agents = []
        if role in {'admin', 'manager'}:
            cursor.execute("""
                SELECT id, username, full_name, role
                FROM users
                WHERE LOWER(TRIM(role)) IN ('admin','manager','user','caller','tele caller','telecaller')
                ORDER BY COALESCE(NULLIF(full_name, ''), username)
            """)
            available_agents = [dict(row) for row in cursor.fetchall()]

        return {
            "agent": dict(agent),
            "days": safe_days,
            "from": from_date.isoformat(),
            "to": today.isoformat(),
            "summary": summary,
            "overdue": overdue_items,
            "agents": available_agents,
        }

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

@api_router.get("/users/assignable")
def get_assignable_users(current_user: dict = Depends(get_current_user)):
    """Get users available for reminder assignment."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, full_name, email, role
            FROM users
            ORDER BY COALESCE(NULLIF(full_name, ''), username)
        """)
        users = []
        for row in cursor.fetchall():
            item = dict(row)
            item['is_current_user'] = item.get('id') == current_user.get('id')
            users.append(item)
        return users

@api_router.post("/team/assign-lead")
def assign_lead_to_member(lead_id: int, user_id: int, current_user: dict = Depends(get_current_user)):
    """Assign a lead to a team member"""
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_collaboration_tables(cursor)
        try:
            cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Team member not found")
            cursor.execute("SELECT id FROM leads WHERE id = %s", (lead_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Lead not found")
            cursor.execute("DELETE FROM lead_assignments WHERE lead_id = %s", (lead_id,))
            cursor.execute("""
                INSERT INTO lead_assignments (lead_id, user_id, assigned_by)
                VALUES (%s, %s, %s)
            """, (lead_id, user_id, current_user['id']))
            cursor.execute("UPDATE leads SET assigned_to = %s WHERE id = %s", (user_id, lead_id))
            conn.commit()
            return {"message": "Lead assigned successfully"}
        except HTTPException:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise

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

@api_router.get("/user/feature-flags")
def get_current_user_feature_flags(current_user: dict = Depends(get_current_user)):
    """Return the current user's independently managed mobile app access."""
    is_admin = str(current_user.get("role") or "").strip().lower() == "admin"
    with get_db() as conn:
        cursor = conn.cursor()
        ensure_user_mobile_feature_flags_table(cursor)
        conn.commit()
        return {
            "is_admin": is_admin,
            "flags": get_user_mobile_feature_flag_values(cursor, int(current_user["id"])),
        }

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
