"""
ai4.py — AWU Shopping HIPS (Host Intrusion Prevention System)
Cross-platform: Windows + Linux + macOS
"""

import time
import os
import hashlib
import logging
import subprocess
import platform
import psutil
import getpass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

MONITORED_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WHITELIST      = ["127.0.0.1", "8.8.8.8", "1.1.1.1"]
RISK_THRESHOLD = 7
OS_TYPE        = platform.system()  # 'Windows', 'Linux', 'Darwin'

file_hashes = {}
blocked_ips = set()

logging.basicConfig(
    filename="security_log.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def show_alert(msg: str):
    """Show a security alert — platform-aware."""
    print(f"\n{'='*50}")
    print(f"  ⚠  SECURITY ALERT")
    print(f"{'='*50}")
    print(msg)
    print(f"{'='*50}\n")
    logging.warning(f"ALERT: {msg.replace(chr(10), ' | ')}")

    if OS_TYPE == "Windows":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, msg, "AWU Security Alert", 0x30)
        except Exception:
            pass  # Fallback to console if ctypes fails

    elif OS_TYPE == "Linux":
        try:
            # Try notify-send for desktop notification
            subprocess.run(
                ["notify-send", "AWU Security Alert", msg],
                timeout=3, capture_output=True
            )
        except Exception:
            pass  # Console output is the fallback

    elif OS_TYPE == "Darwin":  # macOS
        try:
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{msg}" with title "AWU Security Alert"'],
                timeout=3, capture_output=True
            )
        except Exception:
            pass

def block_ip(ip: str):
    """Block an IP address — platform-aware."""
    if ip in blocked_ips:
        return

    success = False

    if OS_TYPE == "Windows":
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Block_{ip}",
                "dir=in", "action=block",
                f"remoteip={ip}"
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            success = result.returncode == 0
        except Exception as e:
            logging.error(f"Windows firewall block failed: {e}")

    elif OS_TYPE == "Linux":
        try:
            # Try iptables first
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            if result.returncode == 0:
                success = True
            else:
                # Try ufw
                cmd = ["ufw", "deny", "from", ip]
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                success = result.returncode == 0
        except Exception as e:
            logging.error(f"Linux firewall block failed: {e}")

    elif OS_TYPE == "Darwin":  # macOS
        try:
            # macOS pf firewall
            cmd = f'echo "block in from {ip} to any" | pfctl -f -'
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            success = result.returncode == 0
        except Exception as e:
            logging.error(f"macOS firewall block failed: {e}")

    blocked_ips.add(ip)

    status = "SUCCESS" if success else "LOGGED_ONLY (insufficient permissions)"
    logging.warning(f"IP BLOCK [{OS_TYPE}] [{status}]: {ip}")
    print(f"[!] Block IP {ip} — {status}")

def calculate_hash(filepath: str):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def get_username() -> str:
    return getpass.getuser()

def get_process_using_file(filepath: str):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for item in proc.open_files() or []:
                if filepath in item.path:
                    return proc.info
        except Exception:
            continue
    return None

def get_process_remote_ip(pid: int):
    try:
        proc = psutil.Process(pid)
        for conn in proc.connections(kind='inet'):
            if conn.raddr:
                return conn.raddr.ip
    except Exception:
        return None
    return None

def calculate_risk(filepath: str, event_type: str) -> int:
    risk = 0
    ext = os.path.splitext(filepath)[1].lower()

    if ext in (".exe", ".bat", ".sh"):
        risk += 7
    elif ext in (".dll", ".so"):
        risk += 6
    elif ext in (".php", ".py"):
        risk += 5
    elif ext in (".html", ".css", ".js"):
        risk += 3
    else:
        risk += 2

    if event_type == "DELETED":
        risk += 4
    elif event_type == "MOVED":
        risk += 2

    return risk

class SecurityHandler(FileSystemEventHandler):

    IGNORED = {"security_log.log", "security_fallback.log",
                "manager_audit.log", "security_events.jsonl",
                "security_events.log", ".log_key",
                "ai4.py", "security_api.py"}

    def _is_ignored(self, path: str) -> bool:
        filename = os.path.basename(path)
        return (filename in self.IGNORED or
                filename.endswith(".tmp") or
                "\\logs\\" in path or "/logs/" in path)

    def process_event(self, event, event_type: str):
        if event.is_directory:
            return
        filepath = event.src_path
        if self._is_ignored(filepath):
            return

        username     = get_username()
        risk         = calculate_risk(filepath, event_type)
        current_hash = calculate_hash(filepath)
        prev_hash    = file_hashes.get(filepath)

        if prev_hash and current_hash and prev_hash != current_hash:
            risk += 3

        file_hashes[filepath] = current_hash

        process_info = get_process_using_file(filepath)
        pid          = None
        process_name = "Unknown"
        remote_ip    = None

        if process_info:
            pid          = process_info['pid']
            process_name = process_info['name']
            remote_ip    = get_process_remote_ip(pid)

        log_msg = (
            f"EVENT: {event_type} | File: {filepath} | "
            f"User: {username} | Process: {process_name} | "
            f"PID: {pid} | IP: {remote_ip} | Risk: {risk} | OS: {OS_TYPE}"
        )
        logging.info(log_msg)
        print(log_msg)

        if risk >= RISK_THRESHOLD:
            alert_msg = (
                f"HIGH RISK DETECTED\n\n"
                f"OS: {OS_TYPE}\n"
                f"File: {filepath}\n"
                f"Event: {event_type}\n"
                f"Process: {process_name}\n"
                f"Risk Score: {risk}"
            )
            show_alert(alert_msg)

            if remote_ip and remote_ip not in WHITELIST:
                block_ip(remote_ip)

    def on_created(self,  event): self.process_event(event, "CREATED")
    def on_deleted(self,  event): self.process_event(event, "DELETED")
    def on_modified(self, event): self.process_event(event, "MODIFIED")
    def on_moved(self,    event): self.process_event(event, "MOVED")

def initialize_hashes():
    count = 0
    for root, dirs, files in os.walk(MONITORED_PATH):
        for file in files:
            path = os.path.join(root, file)
            file_hashes[path] = calculate_hash(path)
            count += 1
    print(f"[+] Baseline hashes initialized ({count} files)")

if __name__ == "__main__":
    print("=" * 55)
    print("  AWU Shopping — Advanced HIPS Monitor")
    print(f"  Platform: {OS_TYPE}")
    print(f"  Watching: {MONITORED_PATH}")
    print("=" * 55)

    initialize_hashes()


    handler  = SecurityHandler()
    observer = Observer()
    observer.schedule(handler, MONITORED_PATH, recursive=True)
    observer.start()
    print("[+] Monitoring started...\n")

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[+] HIPS stopped.")
    observer.join()