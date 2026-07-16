"""
AWU Shopping - Python Security Module
======================================
Flask-based security API for AWU Shopping platform.
Handles: SQLi, XSS, Brute Force, Input Sanitization, CSRF,
         Path Traversal, Command Injection, Rate Limiting,
         Log Monitoring, Bans, and Reporting.

Usage: Run this Flask server alongside your PHP/XAMPP site.
       PHP calls these endpoints via HTTP (cURL or file_get_contents).
"""

from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import re
import html
import hashlib
import json
import os
import threading

from detectors import (
    detect_sql_injection,
    detect_xss,
    detect_command_injection,
    detect_path_traversal,
    detect_open_redirect,
)
from brute_force import BruteForceProtector
from otp_limiter import otp_limiter
from sanitizer import sanitize_input
from ban_manager import BanManager
from logger import SecurityLogger
from reporter import SecurityReporter

def _load_env(path):
    """
    Minimal, dependency-free .env parser mirroring api/env.php's exact
    logic, so both PHP and Python read the same value the same way
    without adding python-dotenv as a new dependency for one value.
    """
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            if key:
                os.environ[key] = value

# .env lives at the project root, one level above awu_security/
_load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))
INTERNAL_API_SECRET = os.environ.get("INTERNAL_API_SECRET")

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

@app.before_request
def _require_internal_secret():
    if not INTERNAL_API_SECRET:
        # Fail closed: unconfigured means refuse everything, not run wide open.
        return jsonify({"error": "Server misconfigured: INTERNAL_API_SECRET not set"}), 500
    if request.headers.get("X-Internal-Auth") != INTERNAL_API_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

brute_force   = BruteForceProtector()
ban_manager   = BanManager()
sec_logger    = SecurityLogger()
reporter      = SecurityReporter(sec_logger)

def get_client_ip():
    """Extract real client IP (works behind proxies too)."""
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "")
        or request.remote_addr
        or "unknown"
    )

def build_response(safe, threats, sanitized=None, action=None, extra=None):
    resp = {
        "safe":     safe,
        "threats":  threats,
        "action":   action or ("allow" if safe else "block"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    if sanitized is not None:
        resp["sanitized_value"] = sanitized
    if extra:
        resp.update(extra)
    return jsonify(resp)


@app.route("/api/scan", methods=["POST"])
def scan_input():
    """
    Scan a single user-supplied value for all known attack patterns.

    JSON body:
        {
            "value":   "<user input>",
            "field":   "username",        // optional label
            "context": "login",           // optional context
            "user_id": "123"              // optional
        }
    """
    data     = request.get_json(silent=True) or {}
    value    = str(data.get("value", ""))
    field    = data.get("field", "input")
    context  = data.get("context", "general")
    user_id  = data.get("user_id", "anonymous")
    ip       = data.get("ip") or get_client_ip()

    ban_info = ban_manager.is_banned(ip)
    if ban_info["banned"]:
        sec_logger.log_event("BANNED_REQUEST", ip, user_id, field,
                             value[:120], f"Banned until {ban_info['until']}")
        return build_response(False, ["IP_BANNED"], action="block",
                              extra={"ban_until": ban_info["until"],
                                     "reason": ban_info["reason"]}), 403

    threats = []
    sqli_result = detect_sql_injection(value)
    if sqli_result["detected"]:
        threats.append({"type": "SQL_INJECTION", "detail": sqli_result["pattern"]})

    xss_result = detect_xss(value)
    if xss_result["detected"]:
        threats.append({"type": "XSS", "detail": xss_result["pattern"]})

    cmd_result = detect_command_injection(value)
    if cmd_result["detected"]:
        threats.append({"type": "COMMAND_INJECTION", "detail": cmd_result["pattern"]})

    path_result = detect_path_traversal(value)
    if path_result["detected"]:
        threats.append({"type": "PATH_TRAVERSAL", "detail": path_result["pattern"]})

    redirect_result = detect_open_redirect(value)
    if redirect_result["detected"]:
        threats.append({"type": "OPEN_REDIRECT", "detail": redirect_result["pattern"]})

    sanitized = sanitize_input(value)
    safe      = len(threats) == 0

    if not safe:
        threat_names = [t["type"] for t in threats]
        sec_logger.log_event("ATTACK_DETECTED", ip, user_id, field,
                             value[:120], ", ".join(threat_names))
        # Escalating: 3+ attacks → temp ban; 6+ → permanent ban
        strike_count = sec_logger.count_recent_attacks(ip, minutes=10)
        if strike_count >= 6:
            ban_manager.ban_ip(ip, reason="Repeated attacks (≥6 in 10 min)",
                               permanent=True)
            sec_logger.log_event("IP_BANNED_PERMANENT", ip, user_id, field,
                                 value[:120], "Auto-banned: ≥6 attacks in 10 min")
        elif strike_count >= 3:
            ban_manager.ban_ip(ip, reason="Multiple attacks (≥3 in 10 min)",
                               duration_minutes=60)
            sec_logger.log_event("IP_BANNED_TEMP", ip, user_id, field,
                                 value[:120], "Temp-banned 60 min: ≥3 attacks")

    return build_response(safe, threats, sanitized=sanitized)


@app.route("/api/login-attempt", methods=["POST"])
def login_attempt():
    """
    Record a login attempt and decide whether to allow it.

    JSON body:
        { "ip": "...", "email": "...", "success": false }
    """
    data    = request.get_json(silent=True) or {}
    ip      = data.get("ip") or get_client_ip()
    email   = data.get("email", "unknown")
    success = bool(data.get("success", False))

    # ── Ban check ────────────────────────────────────────────────────────────
    ban_info = ban_manager.is_banned(ip)
    if ban_info["banned"]:
        return build_response(False, ["IP_BANNED"], action="block",
                              extra={"ban_until": ban_info["until"],
                                     "message":  "Your IP is temporarily banned."}), 403

    result = brute_force.record_attempt(ip, email, success)

    if result["action"] in ("ban", "lock", "block"):
        duration = result.get("ban_minutes") or 30
        ban_manager.ban_ip(
            ip,
            reason=f"Brute force login ({result['action']})",
            duration_minutes=int(duration)
        )
        sec_logger.log_event("BRUTE_FORCE_BAN", ip, email, "login",
                             "", f"Banned {result.get('ban_minutes',30)} min")
    elif result["action"] == "warn":
        sec_logger.log_event("BRUTE_FORCE_WARN", ip, email, "login",
                             "", f"{result.get('attempts_remaining', 0)} failed attempts")
    elif not success:
        sec_logger.log_event("LOGIN_FAIL", ip, email, "login", "", "")

    return build_response(
        result["action"] not in ("ban", "block"),
        ["BRUTE_FORCE"] if result["action"] in ("ban","block","warn") else [],
        action=result["action"],
        extra={
            "attempts_remaining": result.get("attempts_remaining"),
            "lockout_until":      result.get("lockout_until"),
            "message":            result.get("message", ""),
        }
    )

@app.route("/api/otp/send-check", methods=["POST"])
def otp_send_check():
    """
    Check + record an OTP-send attempt for the given IP.
    JSON body: { "ip": "..." }
    """
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip") or get_client_ip()
    return jsonify(otp_limiter.check_send(ip))


@app.route("/api/otp/verify-check", methods=["POST"])
def otp_verify_check():
    """
    Check + record an OTP-verify attempt for the given IP.
    JSON body: { "ip": "..." }
    """
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip") or get_client_ip()
    return jsonify(otp_limiter.check_verify(ip))

@app.route("/api/sanitize", methods=["POST"])
def sanitize():
    """
    Return a sanitized version of the input value.

    JSON body: { "value": "...", "type": "html|sql|plain" }
    """
    data  = request.get_json(silent=True) or {}
    value = str(data.get("value", ""))
    mode  = data.get("type", "plain")
    clean = sanitize_input(value, mode=mode)
    return jsonify({"original": value, "sanitized": clean, "mode": mode})


@app.route("/api/ban", methods=["POST"])
def ban_ip():
    """
    Manually ban an IP.
    JSON body: { "ip": "...", "reason": "...", "duration_minutes": 60 }
    """
    data     = request.get_json(silent=True) or {}
    ip       = data.get("ip", "")
    reason   = data.get("reason", "Manual ban")
    duration = int(data.get("duration_minutes", 60))
    permanent = data.get("permanent", False)

    if not ip:
        return jsonify({"error": "IP required"}), 400

    ban_manager.ban_ip(ip, reason=reason, duration_minutes=duration,
                       permanent=permanent)
    sec_logger.log_event("MANUAL_BAN", ip, "admin", "ban", "", reason)
    return jsonify({"status": "banned", "ip": ip, "reason": reason,
                    "permanent": permanent, "duration_minutes": duration})


@app.route("/api/unban", methods=["POST"])
def unban_ip():
    """Manually unban an IP. JSON body: { "ip": "..." }"""
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    ban_manager.unban_ip(ip)
    sec_logger.log_event("MANUAL_UNBAN", ip, "admin", "unban", "", "")
    return jsonify({"status": "unbanned", "ip": ip})


@app.route("/api/ban/check", methods=["GET"])
def check_ban():
    """Check if an IP is banned. Query param: ?ip=x.x.x.x"""
    ip = request.args.get("ip", get_client_ip())
    return jsonify(ban_manager.is_banned(ip))


@app.route("/api/report", methods=["GET"])
def get_report():
    """
    Return a full security report.
    Query params: ?hours=24&format=json
    """
    hours  = int(request.args.get("hours", 24))
    report = reporter.generate_report(hours=hours)
    return jsonify(report)


@app.route("/api/report/summary", methods=["GET"])
def get_summary():
    """Quick summary – top attackers, attack counts by type."""
    hours   = int(request.args.get("hours", 24))
    summary = reporter.generate_summary(hours=hours)
    return jsonify(summary)


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    Return recent log entries.
    Query params: ?limit=50&event_type=ATTACK_DETECTED&ip=x.x.x.x
    """
    limit      = int(request.args.get("limit", 50))
    event_type = request.args.get("event_type")
    ip_filter  = request.args.get("ip")
    entries    = sec_logger.get_recent(limit=limit, event_type=event_type,
                                       ip_filter=ip_filter)
    return jsonify({"count": len(entries), "logs": entries})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":    "online",
        "service":   "AWU Security Module",
        "version":   "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
@app.route('/api/ban/list', methods=['GET'])
def list_bans():
    bans = ban_manager.list_bans()
    return jsonify({'bans': bans})
@app.route('/api/reset-brute-force', methods=['POST'])
def reset_brute_force():
    data = request.get_json(silent=True) or {}
    ip   = data.get('ip', '')
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    brute_force.reset(ip)
    return jsonify({'status': 'reset', 'ip': ip})
if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    print("=" * 55)
    print("  AWU Shopping – Security API")
    print("=" * 55)
    ssl_cert = os.path.join(os.path.dirname(__file__), "ssl", "api_cert.pem")
    ssl_key  = os.path.join(os.path.dirname(__file__), "ssl", "api_key.pem")

    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        print("  Running on https://127.0.0.1:5000")
        print("  SSL: ENABLED (HTTPS)")
        app.run(host="127.0.0.1", port=5000, debug=False,
                ssl_context=(ssl_cert, ssl_key))
    else:
        print("  SSL: DISABLED (run generate_cert.py first)")
        app.run(host="127.0.0.1", port=5000, debug=False)