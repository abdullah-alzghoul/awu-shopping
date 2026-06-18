"""
brute_force.py – Brute Force & Rate Limiting Protection
=========================================================
Tracks failed login attempts per IP and per email.
Implements progressive lockouts and auto-ban escalation.

Strategy:
  - 5  failures in 5 min  → warn user (show captcha hint)
  - 10 failures in 5 min  → lock IP for 30 minutes
  - 20 failures in 1 hour → lock IP for 24 hours
  - Persistent offenders  → escalate to BanManager
"""

from datetime import datetime, timedelta
from collections import defaultdict
import threading
import json
import os

# ── Config ───────────────────────────────────────────────────────────────────
WARN_THRESHOLD       = 5    # attempts before warning
LOCK_THRESHOLD       = 10   # attempts before 30-min lock
HARD_LOCK_THRESHOLD  = 20   # attempts before 24-hour lock
WINDOW_MINUTES       = 10    # rolling window for soft lock
HARD_WINDOW_MINUTES  = 60   # rolling window for hard lock
LOCK_DURATION_MIN    = 30   # soft lockout duration (minutes)
HARD_LOCK_DURATION_H = 24   # hard lockout duration (hours)
PERSISTENCE_FILE     = "logs/brute_force_state.json"


class BruteForceProtector:
    """Thread-safe brute-force tracker with persistence."""

    def __init__(self):
        self._lock     = threading.Lock()
        # Structure: { ip: [ {"time": ISO, "email": str, "success": bool} ] }
        self._attempts = defaultdict(list)
        # Structure: { ip: {"until": ISO, "reason": str} }
        self._lockouts = {}
        self._load_state()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load_state(self):
        """Load saved state from disk so lockouts survive restarts."""
        os.makedirs("logs", exist_ok=True)
        if os.path.exists(PERSISTENCE_FILE):
            try:
                with open(PERSISTENCE_FILE) as f:
                    data = json.load(f)
                self._lockouts  = data.get("lockouts", {})
                raw_attempts    = data.get("attempts", {})
                self._attempts  = defaultdict(list, raw_attempts)
            except Exception:
                pass  # corrupt file – start fresh

    def _save_state(self):
        """Persist current state to disk."""
        try:
            with open(PERSISTENCE_FILE, "w") as f:
                json.dump({
                    "lockouts": self._lockouts,
                    "attempts": dict(self._attempts),
                }, f, indent=2)
        except Exception:
            pass

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _prune(self, ip: str, window_minutes: int = HARD_WINDOW_MINUTES):
        """Remove attempt records outside the given rolling window."""
        cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
        self._attempts[ip] = [
            a for a in self._attempts[ip] if a["time"] >= cutoff
        ]

    def _failed_in_window(self, ip: str, minutes: int) -> int:
        """Count failed attempts for ip within the last `minutes` minutes."""
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        return sum(
            1 for a in self._attempts[ip]
            if a["time"] >= cutoff and not a["success"]
        )

    def _is_locked(self, ip: str) -> dict:
        """Return lockout info if IP is currently locked."""
        info = self._lockouts.get(ip)
        if not info:
            return {"locked": False}
        until_dt = datetime.fromisoformat(info["until"])
        if datetime.utcnow() < until_dt:
            remaining = int((until_dt - datetime.utcnow()).total_seconds() // 60)
            return {
                "locked":    True,
                "until":     info["until"],
                "reason":    info["reason"],
                "remaining_minutes": remaining,
            }
        # Lockout expired – clean up
        del self._lockouts[ip]
        return {"locked": False}

    # ── Public API ───────────────────────────────────────────────────────────

    def record_attempt(self, ip: str, email: str, success: bool) -> dict:
        """
        Record a login attempt and return an action decision.

        Returns dict:
            {
                "action":             "allow" | "warn" | "lock" | "ban",
                "attempts_remaining": int | None,
                "lockout_until":      ISO str | None,
                "ban_minutes":        int | None,
                "message":            str,
            }
        """
        with self._lock:
            # Check existing lockout first
            lock_info = self._is_locked(ip)
            if lock_info["locked"]:
                return {
                    "action":             "block",
                    "attempts_remaining": 0,
                    "lockout_until":      lock_info["until"],
                    "ban_minutes":        None,
                    "message": (
                        f"IP locked. Try again in "
                        f"{lock_info['remaining_minutes']} minutes."
                    ),
                }

            # Record attempt
            self._prune(ip)
            self._attempts[ip].append({
                "time":    datetime.utcnow().isoformat(),
                "email":   email,
                "success": success,
            })

            if success:
                # Clear failed attempts on successful login
                self._attempts[ip] = [
                    a for a in self._attempts[ip] if a["success"]
                ]
                self._save_state()
                return {
                    "action": "allow", "attempts_remaining": None,
                    "lockout_until": None, "ban_minutes": None,
                    "message": "Login successful.",
                }

            # Count recent failures
            soft_fails = self._failed_in_window(ip, WINDOW_MINUTES)
            hard_fails = self._failed_in_window(ip, HARD_WINDOW_MINUTES)

            # Hard lock (24h)
            if hard_fails >= HARD_LOCK_THRESHOLD:
                until = (datetime.utcnow() +
                         timedelta(hours=HARD_LOCK_DURATION_H)).isoformat()
                self._lockouts[ip] = {
                    "until":  until,
                    "reason": f"Hard lock: {hard_fails} failures in {HARD_WINDOW_MINUTES} min",
                }
                self._save_state()
                return {
                    "action":             "ban",
                    "attempts_remaining": 0,
                    "lockout_until":      until,
                    "ban_minutes":        HARD_LOCK_DURATION_H * 60,
                    "message": "Account locked for 24 hours due to repeated failures.",
                }

            # Soft lock (30 min)
            if soft_fails >= LOCK_THRESHOLD:
                until = (datetime.utcnow() +
                         timedelta(minutes=LOCK_DURATION_MIN)).isoformat()
                self._lockouts[ip] = {
                    "until":  until,
                    "reason": f"Soft lock: {soft_fails} failures in {WINDOW_MINUTES} min",
                }
                self._save_state()
                return {
                    "action":             "lock",
                    "attempts_remaining": 0,
                    "lockout_until":      until,
                    "ban_minutes":        LOCK_DURATION_MIN,
                    "message": f"Too many failed attempts. Try again in {LOCK_DURATION_MIN} minutes.",
                }

            # Warning zone
            if soft_fails >= WARN_THRESHOLD:
                remaining = LOCK_THRESHOLD - soft_fails
                self._save_state()
                return {
                    "action":             "warn",
                    "attempts_remaining": remaining,
                    "lockout_until":      None,
                    "ban_minutes":        None,
                    "message": (
                        f"Warning: {remaining} attempt(s) left before lockout."
                    ),
                }

            # Normal failure
            remaining = LOCK_THRESHOLD - soft_fails
            self._save_state()
            return {
                "action":             "allow",
                "attempts_remaining": remaining,
                "lockout_until":      None,
                "ban_minutes":        None,
                "message": "Invalid credentials.",
            }

    def get_status(self, ip: str) -> dict:
        """Return current status for an IP (for debugging/admin)."""
        with self._lock:
            self._prune(ip)
            lock_info  = self._is_locked(ip)
            soft_fails = self._failed_in_window(ip, WINDOW_MINUTES)
            hard_fails = self._failed_in_window(ip, HARD_WINDOW_MINUTES)
            return {
                "ip":           ip,
                "locked":       lock_info.get("locked", False),
                "lockout_info": lock_info,
                "soft_fails":   soft_fails,
                "hard_fails":   hard_fails,
                "all_attempts": len(self._attempts[ip]),
            }

    def reset(self, ip: str):
        """Manually reset attempts and lockout for an IP (admin action)."""
        with self._lock:
            self._attempts.pop(ip, None)
            self._lockouts.pop(ip, None)
            self._save_state()
