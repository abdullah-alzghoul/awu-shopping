"""
ban_manager.py – IP Ban Management
====================================
Manages temporary and permanent IP bans.
Bans persist across restarts via JSON file.
"""

import json
import os
import threading
from datetime import datetime, timedelta

BAN_FILE = "logs/bans.json"


class BanManager:
    """Thread-safe IP ban manager with file persistence."""

    def __init__(self):
        self._lock = threading.Lock()
        # Structure: { ip: { "until": ISO|"permanent", "reason": str, "created": ISO } }
        self._bans = {}
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self):
        os.makedirs("logs", exist_ok=True)
        if os.path.exists(BAN_FILE):
            try:
                with open(BAN_FILE) as f:
                    self._bans = json.load(f)
            except Exception:
                self._bans = {}

    def _save(self):
        try:
            with open(BAN_FILE, "w") as f:
                json.dump(self._bans, f, indent=2)
        except Exception:
            pass

    # ── Public API ───────────────────────────────────────────────────────────

    def ban_ip(self, ip: str, reason: str = "Security violation",
               duration_minutes: int = 60, permanent: bool = False):
        """
        Ban an IP address.

        Args:
            ip:               IP address to ban.
            reason:           Human-readable reason.
            duration_minutes: How long for temp bans (ignored if permanent=True).
            permanent:        If True, ban never expires.
        """
        with self._lock:
            if permanent:
                until = "permanent"
            else:
                until = (datetime.utcnow() +
                         timedelta(minutes=duration_minutes)).isoformat()
            self._bans[ip] = {
                "until":   until,
                "reason":  reason,
                "created": datetime.utcnow().isoformat(),
            }
            self._save()

    def unban_ip(self, ip: str):
        """Remove a ban for the given IP."""
        with self._lock:
            self._bans.pop(ip, None)
            self._save()

    def is_banned(self, ip: str) -> dict:
        """
        Check if an IP is currently banned.

        Returns:
            { "banned": bool, "reason": str, "until": str }
        """
        with self._lock:
            info = self._bans.get(ip)
            if not info:
                return {"banned": False, "reason": None, "until": None}

            if info["until"] == "permanent":
                return {
                    "banned": True,
                    "reason": info["reason"],
                    "until":  "permanent",
                }

            until_dt = datetime.fromisoformat(info["until"])
            if datetime.utcnow() < until_dt:
                return {
                    "banned": True,
                    "reason": info["reason"],
                    "until":  info["until"],
                }

            # Expired – auto-remove
            del self._bans[ip]
            self._save()
            return {"banned": False, "reason": None, "until": None}

    def list_bans(self) -> list:
        """Return all active bans (auto-removes expired ones)."""
        with self._lock:
            now     = datetime.utcnow()
            active  = []
            expired = []

            for ip, info in self._bans.items():
                if info["until"] == "permanent":
                    active.append({"ip": ip, **info})
                elif datetime.fromisoformat(info["until"]) > now:
                    active.append({"ip": ip, **info})
                else:
                    expired.append(ip)

            for ip in expired:
                del self._bans[ip]
            if expired:
                self._save()

            return active

    def ban_count(self) -> dict:
        """Return counts of active bans by type."""
        bans      = self.list_bans()
        permanent = sum(1 for b in bans if b["until"] == "permanent")
        temporary = len(bans) - permanent
        return {"total": len(bans), "permanent": permanent, "temporary": temporary}
