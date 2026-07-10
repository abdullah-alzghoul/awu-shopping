"""
otp_limiter.py – Rate limiting for OTP send/verify actions, per IP.
=====================================================================
Separate from brute_force.py (which is login-specific) since OTP send
and verify actions need much tighter, simpler limits than login
brute-force protection — and mixing the two into one shared counter
would mean a mistyped password could also lock someone out of
requesting a legitimate password-reset code, or vice versa.

Same persistence pattern as brute_force.py: thread-safe, JSON state
file, survives restarts.
"""

from datetime import datetime, timedelta
from collections import defaultdict
import threading
import json
import os

SEND_LIMIT        = 3    # max OTP sends per window
SEND_WINDOW_MIN   = 10
VERIFY_LIMIT      = 5    # max verification attempts per window
VERIFY_WINDOW_MIN = 10
PERSISTENCE_FILE  = "logs/otp_limiter_state.json"


class OtpLimiter:
    """Thread-safe, IP-persistent rate limiter for OTP send/verify actions."""

    def __init__(self):
        self._lock = threading.Lock()
        self._state = defaultdict(lambda: {"sends": [], "verifies": []})
        self._load_state()

    def _load_state(self):
        os.makedirs("logs", exist_ok=True)
        if os.path.exists(PERSISTENCE_FILE):
            try:
                with open(PERSISTENCE_FILE) as f:
                    data = json.load(f)
                self._state = defaultdict(lambda: {"sends": [], "verifies": []}, data)
            except Exception:
                pass  # corrupt file - start fresh

    def _save_state(self):
        try:
            with open(PERSISTENCE_FILE, "w") as f:
                json.dump(dict(self._state), f)
        except Exception:
            pass

    def _prune(self, timestamps, window_minutes):
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        return [t for t in timestamps if datetime.fromisoformat(t) > cutoff]

    def _check(self, ip, key, limit, window_minutes):
        with self._lock:
            entry = self._state[ip]
            entry[key] = self._prune(entry[key], window_minutes)
            if len(entry[key]) >= limit:
                oldest = datetime.fromisoformat(entry[key][0])
                retry_after = int((oldest + timedelta(minutes=window_minutes)
                                    - datetime.utcnow()).total_seconds())
                self._save_state()
                return {"allowed": False, "remaining": 0,
                        "retry_after_seconds": max(retry_after, 0)}
            entry[key].append(datetime.utcnow().isoformat())
            self._save_state()
            return {"allowed": True, "remaining": limit - len(entry[key]),
                     "retry_after_seconds": 0}

    def check_send(self, ip: str) -> dict:
        """Check + record an OTP-send attempt for this IP."""
        return self._check(ip, "sends", SEND_LIMIT, SEND_WINDOW_MIN)

    def check_verify(self, ip: str) -> dict:
        """Check + record an OTP-verify attempt for this IP."""
        return self._check(ip, "verifies", VERIFY_LIMIT, VERIFY_WINDOW_MIN)


otp_limiter = OtpLimiter()