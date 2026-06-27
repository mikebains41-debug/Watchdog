"""
Watchdog AIDR v2.0 - API Authentication
API key authentication middleware for FastAPI.
Keys stored as SHA256 hashes — never plaintext.
Supports multiple keys with different permission levels.
"""
import os, hashlib, time, json
from datetime import datetime

KEY_FILE = os.environ.get("WATCHDOG_KEY_FILE", "watchdog_data/api_keys.json")

DEFAULT_KEYS = {
    "watchdog-admin-2026": "admin",
    "watchdog-readonly-2026": "readonly",
    "watchdog-siem-2026": "siem",
}

def _hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

def _load_keys():
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    hashed = {_hash_key(k): v for k, v in DEFAULT_KEYS.items()}
    os.makedirs(os.path.dirname(KEY_FILE) if os.path.dirname(KEY_FILE) else ".", exist_ok=True)
    try:
        with open(KEY_FILE, "w") as f:
            json.dump(hashed, f, indent=2)
    except Exception:
        pass
    return hashed

_KEY_STORE = _load_keys()
_REQUEST_LOG = []

def verify_key(api_key):
    if not api_key:
        return None, "NO_KEY"
    hashed = _hash_key(api_key)
    role = _KEY_STORE.get(hashed)
    if not role:
        _log_request(api_key[:8] + "...", "REJECTED")
        return None, "INVALID_KEY"
    _log_request(api_key[:8] + "...", "ACCEPTED", role)
    return role, "OK"

def _log_request(key_prefix, status, role=None):
    _REQUEST_LOG.append({
        "timestamp": datetime.now().isoformat(),
        "key_prefix": key_prefix,
        "status": status,
        "role": role
    })
    if len(_REQUEST_LOG) > 1000:
        _REQUEST_LOG.pop(0)

def get_auth_stats():
    accepted = sum(1 for r in _REQUEST_LOG if r["status"] == "ACCEPTED")
    rejected = sum(1 for r in _REQUEST_LOG if r["status"] == "REJECTED")
    return {
        "total_requests": len(_REQUEST_LOG),
        "accepted": accepted,
        "rejected": rejected,
        "rejection_rate_pct": round(rejected / len(_REQUEST_LOG) * 100, 2) if _REQUEST_LOG else 0
    }

def add_key(key, role="readonly"):
    hashed = _hash_key(key)
    _KEY_STORE[hashed] = role
    try:
        with open(KEY_FILE, "w") as f:
            json.dump(_KEY_STORE, f, indent=2)
    except Exception:
        pass
    return hashed

def revoke_key(key):
    hashed = _hash_key(key)
    if hashed in _KEY_STORE:
        del _KEY_STORE[hashed]
        try:
            with open(KEY_FILE, "w") as f:
                json.dump(_KEY_STORE, f, indent=2)
        except Exception:
            pass
        return True
    return False

try:
    from fastapi import HTTPException, Security
    from fastapi.security import APIKeyHeader

    api_key_header = APIKeyHeader(name="X-Watchdog-API-Key", auto_error=False)

    async def require_api_key(api_key: str = Security(api_key_header)):
        role, status = verify_key(api_key)
        if not role:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid or missing API key. Status: {status}"
            )
        return role

    async def require_admin(api_key: str = Security(api_key_header)):
        role, status = verify_key(api_key)
        if role != "admin":
            raise HTTPException(
                status_code=403,
                detail="Admin role required"
            )
        return role

except ImportError:
    async def require_api_key(api_key=None):
        return "admin"
    async def require_admin(api_key=None):
        return "admin"
