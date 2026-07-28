# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
api/rate_limit.py

Brute-force protection and persistent audit logging for api/auth.py.

WHY THIS IS SEPARATE FROM verify_key(): rate limiting needs to know
WHO is making the attempt, and verify_key(api_key) only receives the
key itself -- it has no access to the request or client address. The
enforcement point therefore has to be the FastAPI dependency layer,
where the Request object is available. Keeping it in its own module
also means auth.py's existing, working key logic is untouched.

WHAT THIS ADDS, both of which were genuinely absent before:

  1. Brute-force protection. Before this, an attacker could attempt
     unlimited API keys as fast as the network allowed -- verify_key()
     hashed, compared, logged, and returned None, with nothing
     counting failures or slowing anything down. Now: MAX_FAILURES
     failures from one client within FAILURE_WINDOW_S blocks that
     client for BLOCK_DURATION_S. A successful auth clears that
     client's failure count.

  2. Persistence. auth.py's _REQUEST_LOG is in-memory only, so the
     audit trail vanished on restart. Both the log and any active
     blocks are now written to disk, following the same
     load-on-import / save-on-write pattern auth.py already uses for
     api_keys.json. Expired blocks are dropped on load rather than
     resurrected.

HONEST LIMITS, stated rather than left to be discovered:

  - Client identity is whatever the caller passes in, normally the
    peer address. Behind a proxy or load balancer that is the
    proxy's address, not the real client's, unless the deployment
    forwards it properly -- in which case every request appears to
    come from one client and blocking one blocks everyone. Any
    deployment behind a proxy needs to pass the forwarded client
    address explicitly.
  - Blocks are per-process. Multiple Watchdog API processes do not
    share state; the disk file is written by each independently and
    last-write-wins. This is adequate for a single-instance
    deployment and is NOT a distributed rate limiter.
  - This does not defend against a distributed attempt from many
    addresses. It raises the cost of guessing from one source.
"""
import json
import os
import time
from collections import defaultdict

AUTH_DIR = "watchdog_data"
LOG_FILE = os.path.join(AUTH_DIR, "auth_log.json")

MAX_FAILURES = 5
FAILURE_WINDOW_S = 300
BLOCK_DURATION_S = 900
MAX_LOG_ENTRIES = 1000

_FAILURES = defaultdict(list)
_BLOCKED = {}
_REQUEST_LOG = []


def _now():
    return time.time()


def is_blocked(client_id):
    """Returns (blocked: bool, seconds_remaining: int). Clears the
    block and the client's failure history once it has expired."""
    until = _BLOCKED.get(client_id)
    if until is None:
        return False, 0
    if _now() >= until:
        del _BLOCKED[client_id]
        _FAILURES.pop(client_id, None)
        _save_log()
        return False, 0
    return True, int(until - _now())


def record_failure(client_id):
    """Records a failed auth attempt. Returns True if this attempt
    triggered a block. Only failures inside the rolling window count,
    so slow guessing across hours does not accumulate indefinitely."""
    now = _now()
    cutoff = now - FAILURE_WINDOW_S
    _FAILURES[client_id] = [t for t in _FAILURES[client_id] if t > cutoff]
    _FAILURES[client_id].append(now)
    if len(_FAILURES[client_id]) >= MAX_FAILURES:
        _BLOCKED[client_id] = now + BLOCK_DURATION_S
        _save_log()
        return True
    return False


def record_success(client_id):
    """Clears a client's failure history after a successful auth."""
    _FAILURES.pop(client_id, None)


def log_request(key_prefix, status, client_id="unknown"):
    """Appends to the persistent audit log, capped at MAX_LOG_ENTRIES."""
    _REQUEST_LOG.append({
        "ts": _now(),
        "prefix": key_prefix,
        "status": status,
        "client": client_id,
    })
    if len(_REQUEST_LOG) > MAX_LOG_ENTRIES:
        _REQUEST_LOG.pop(0)
    _save_log()


def get_stats():
    now = _now()
    return {
        "logged_requests": len(_REQUEST_LOG),
        "currently_blocked": [
            {"client": k, "seconds_remaining": int(v - now)}
            for k, v in _BLOCKED.items() if v > now
        ],
        "clients_with_recent_failures": len(_FAILURES),
        "config": {
            "max_failures": MAX_FAILURES,
            "failure_window_s": FAILURE_WINDOW_S,
            "block_duration_s": BLOCK_DURATION_S,
        },
    }


def _save_log():
    try:
        os.makedirs(AUTH_DIR, exist_ok=True)
        with open(LOG_FILE, "w") as f:
            json.dump({
                "requests": _REQUEST_LOG[-MAX_LOG_ENTRIES:],
                "blocked": _BLOCKED,
            }, f)
        return True
    except Exception:
        return False


def _load_log():
    """Restores the audit log and any still-active blocks. Expired
    blocks are dropped rather than restored."""
    global _REQUEST_LOG, _BLOCKED
    if not os.path.exists(LOG_FILE):
        return
    try:
        with open(LOG_FILE) as f:
            data = json.load(f)
        _REQUEST_LOG = data.get("requests", [])
        now = _now()
        _BLOCKED = {k: v for k, v in data.get("blocked", {}).items() if v > now}
    except Exception:
        pass


_load_log()
