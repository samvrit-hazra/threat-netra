import uuid
from typing import Dict, Any, Optional
from src.auth.backend.config import OWNER_EMAIL, DEMO_EMAIL, DEMO_PASSWORD

# In-memory mock database for development/offline testing
MOCK_USERS: Dict[str, Dict[str, Any]] = {
    "admin-uuid-001": {
        "id": "admin-uuid-001",
        "email": OWNER_EMAIL,
        "password": "password123",
        "full_name": "Website Owner",
        "role": "admin",
        "status": "approved"
    },
    "demo-uuid-002": {
        "id": "demo-uuid-002",
        "email": DEMO_EMAIL,
        "password": DEMO_PASSWORD,
        "full_name": "Demo Evaluator",
        "role": "governmental_user",
        "status": "approved"
    },
    "sample-gov-uuid-003": {
        "id": "sample-gov-uuid-003",
        "email": "analyst@defence.gov.in",
        "password": "password123",
        "full_name": "Gov Threat Analyst",
        "role": "governmental_user",
        "status": "approved"
    },
    "sample-norm-uuid-004": {
        "id": "sample-norm-uuid-004",
        "email": "researcher@osintlabs.io",
        "password": "password123",
        "full_name": "OSINT Researcher",
        "role": "normal_user",
        "status": "approved"
    },
    "sample-pending-uuid-005": {
        "id": "sample-pending-uuid-005",
        "email": "pending_applicant@intel.org",
        "password": "password123",
        "full_name": "New Applicant",
        "role": None,
        "status": "pending_approval"
    }
}

MOCK_SESSIONS: Dict[str, str] = {}  # token -> user_id

def create_mock_user(email: str, password: str, full_name: Optional[str] = None) -> Dict[str, Any]:
    user_id = str(uuid.uuid4())
    is_owner = (email.strip().lower() == OWNER_EMAIL)
    user = {
        "id": user_id,
        "email": email.strip().lower(),
        "password": password,
        "full_name": full_name or email.split("@")[0],
        "role": "admin" if is_owner else None,
        "status": "approved" if is_owner else "pending_approval"
    }
    MOCK_USERS[user_id] = user
    return user

def find_mock_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    for u in MOCK_USERS.values():
        if u["email"] == email.strip().lower():
            return u
    return None

def find_mock_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    return MOCK_USERS.get(user_id)

def create_mock_session(user_id: str) -> str:
    token = f"mock-jwt-token-{uuid.uuid4()}"
    MOCK_SESSIONS[token] = user_id
    return token

def get_user_from_mock_token(token: str) -> Optional[Dict[str, Any]]:
    user_id = MOCK_SESSIONS.get(token)
    if user_id:
        return MOCK_USERS.get(user_id)
    # Check for direct demo / test mock tokens
    if token.startswith("mock-jwt-admin"):
        return MOCK_USERS["admin-uuid-001"]
    if token.startswith("mock-jwt-demo"):
        return MOCK_USERS["demo-uuid-002"]
    return None
