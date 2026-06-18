"""
logger.py – Security Event Logger (with basic encryption)
"""

import json
import os
import threading
import base64
import hashlib
from datetime import datetime, timedelta

LOG_JSON = "logs/security_events.jsonl"
LOG_TEXT = "logs/security_events.log"
KEY_FILE = "logs/.log_key"


def _get_key() -> bytes:
    """Get or create encryption key."""
    if not os.path.exists(KEY_FILE):
        os.makedirs("logs", exist_ok=True)
        key = base64.b64encode(os.urandom(32)).decode()
        with open(KEY_FILE, "w") as f:
            f.write(key)
    with open(KEY_FILE, "r") as f:
        raw = f.read().strip()
    return hashlib.sha256(raw.encode()).digest()


def _xor_encrypt(data: str) -> str:
    """XOR encrypt a string and return base64-encoded result."""
    key = _get_key()
    data_bytes = data.encode("utf-8")
    encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data_bytes))
    return base64.b64encode(encrypted).decode()


def _xor_decrypt(encoded: str) -> str:
    """Decrypt a base64-encoded XOR-encrypted string."""
    key = _get_key()
    encrypted = base64.b64decode(encoded.encode())
    decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))
    return decrypted.decode("utf-8")


class SecurityLogger:
    """Thread-safe security event logger with encryption."""

    def __init__(self):
        self._lock = threading.Lock()
        os.makedirs("logs", exist_ok=True)

    def log_event(self, event_type: str, ip: str, user_id: str,
                  field: str, value_preview: str, detail: str):
        timestamp = datetime.utcnow().isoformat() + "Z"

        record = {
            "timestamp":     timestamp,
            "event_type":    event_type,
            "ip":            ip,
            "user_id":       user_id,
            "field":         field,
            "value_preview": value_preview[:120] if value_preview else "",
            "detail":        detail,
        }

        with self._lock:
            
            raw_json = json.dumps(record)
            encrypted_line = _xor_encrypt(raw_json)
            with open(LOG_JSON, "a", encoding="utf-8") as f:
                f.write(encrypted_line + "\n")

            
            with open(LOG_TEXT, "a", encoding="utf-8") as f:
                f.write(
                    f"[{timestamp}] [{event_type}] "
                    f"IP={ip} USER={user_id} FIELD={field} "
                    f"DETAIL={detail} "
                    f"VALUE={value_preview[:60]!r}\n"
                )

    def _read_all(self) -> list:
        """Read and decrypt all log records."""
        records = []
        if not os.path.exists(LOG_JSON):
            return records
        with self._lock:
            with open(LOG_JSON, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        # Try decrypting first
                        decrypted = _xor_decrypt(line)
                        records.append(json.loads(decrypted))
                    except Exception:
                        # Fallback for old plaintext lines
                        try:
                            records.append(json.loads(line))
                        except Exception:
                            pass
        return records

    def get_recent(self, limit: int = 50, event_type: str = None,
                   ip_filter: str = None) -> list:
        records = self._read_all()
        if event_type:
            records = [r for r in records if r["event_type"] == event_type]
        if ip_filter:
            records = [r for r in records if r["ip"] == ip_filter]
        records.sort(key=lambda r: r["timestamp"], reverse=True)
        return records[:limit]

    def count_recent_attacks(self, ip: str, minutes: int = 10) -> int:
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        records = self._read_all()
        return sum(
            1 for r in records
            if r["ip"] == ip
            and r["event_type"] == "ATTACK_DETECTED"
            and r["timestamp"] >= cutoff
        )

    def get_stats(self, hours: int = 24) -> dict:
        cutoff  = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
        records = [r for r in self._read_all() if r["timestamp"] >= cutoff]

        by_type = {}
        ip_counts = {}
        attack_details = {}

        for r in records:
            by_type[r["event_type"]] = by_type.get(r["event_type"], 0) + 1
            if r["event_type"] == "ATTACK_DETECTED":
                ip_counts[r["ip"]] = ip_counts.get(r["ip"], 0) + 1
                detail = r.get("detail", "UNKNOWN")
                attack_details[detail] = attack_details.get(detail, 0) + 1

        top_attackers = sorted(
            [{"ip": ip, "count": c} for ip, c in ip_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:10]

        return {
            "window_hours":    hours,
            "total_events":    len(records),
            "by_type":         by_type,
            "top_attackers":   top_attackers,
            "attack_patterns": attack_details,
        }