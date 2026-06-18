"""
reporter.py – Security Report Generator
=========================================
Generates structured reports from logged security events.
Used by the /api/report and /api/report/summary endpoints.
"""

from datetime import datetime
from logger import SecurityLogger
from ban_manager import BanManager


class SecurityReporter:
    """Builds comprehensive security reports from log data."""

    def __init__(self, logger: SecurityLogger):
        self._logger      = logger
        self._ban_manager = BanManager()

    def generate_report(self, hours: int = 24) -> dict:
        """
        Full security report for the last N hours.

        Returns a structured dict suitable for JSON output or display.
        """
        stats    = self._logger.get_stats(hours=hours)
        bans     = self._ban_manager.list_bans()
        ban_info = self._ban_manager.ban_count()

        # Severity scoring
        attack_count = stats["by_type"].get("ATTACK_DETECTED", 0)
        bf_bans      = stats["by_type"].get("BRUTE_FORCE_BAN", 0)
        if attack_count + bf_bans == 0:
            threat_level = "LOW"
        elif attack_count < 10 and bf_bans < 3:
            threat_level = "MEDIUM"
        elif attack_count < 50:
            threat_level = "HIGH"
        else:
            threat_level = "CRITICAL"

        return {
            "report_generated": datetime.utcnow().isoformat() + "Z",
            "window_hours":     hours,
            "threat_level":     threat_level,
            "summary": {
                "total_events":      stats["total_events"],
                "attacks_detected":  attack_count,
                "brute_force_bans":  bf_bans,
                "login_failures":    stats["by_type"].get("LOGIN_FAIL", 0),
                "manual_bans":       stats["by_type"].get("MANUAL_BAN", 0),
            },
            "attack_patterns": stats["attack_patterns"],
            "event_breakdown":  stats["by_type"],
            "top_attackers":    stats["top_attackers"],
            "active_bans": {
                "total":     ban_info["total"],
                "permanent": ban_info["permanent"],
                "temporary": ban_info["temporary"],
                "list":      bans,
            },
            "recommendations": self._recommendations(stats, threat_level),
        }

    def generate_summary(self, hours: int = 24) -> dict:
        """Lightweight summary – fast, minimal data."""
        stats    = self._logger.get_stats(hours=hours)
        ban_info = self._ban_manager.ban_count()

        attack_count = stats["by_type"].get("ATTACK_DETECTED", 0)

        bf_bans = stats["by_type"].get("BRUTE_FORCE_BAN", 0)
        if attack_count + bf_bans == 0:
            threat_level = "LOW"
        elif attack_count < 10 and bf_bans < 3:
            threat_level = "MEDIUM"
        elif attack_count < 50:
            threat_level = "HIGH"
        else:
            threat_level = "CRITICAL"

        return {
            "window_hours":     hours,
            "total_attacks":    attack_count,
            "threat_level":     threat_level,
            "top_attack_type":  self._top_item(stats["attack_patterns"]),
            "top_attacker_ip":  stats["top_attackers"][0]["ip"]
                                if stats["top_attackers"] else None,
            "active_bans":      ban_info["total"],
            "brute_force_bans": bf_bans,
            "generated_at":     datetime.utcnow().isoformat() + "Z",
        }


    @staticmethod
    def _top_item(counts: dict):
        """Return the key with the highest count, or None."""
        if not counts:
            return None
        return max(counts, key=counts.get)

    @staticmethod
    def _recommendations(stats: dict, threat_level: str) -> list:
        """Generate actionable recommendations based on event data."""
        recs = []

        if stats["by_type"].get("ATTACK_DETECTED", 0) > 20:
            recs.append(
                "High number of attack attempts detected. "
                "Consider enabling Web Application Firewall (WAF) rules."
            )

        if stats["by_type"].get("BRUTE_FORCE_BAN", 0) > 5:
            recs.append(
                "Multiple brute force bans issued. "
                "Consider adding CAPTCHA to the login page."
            )

        sqli_count = stats["attack_patterns"].get("UNION SELECT", 0) + \
                     stats["attack_patterns"].get("Stacked query", 0) + \
                     stats["attack_patterns"].get("SQL comment", 0)
        if sqli_count > 0:
            recs.append(
                f"SQL injection attempts detected ({sqli_count} events). "
                "Verify all DB queries use PDO prepared statements."
            )

        xss_patterns = ["Script tag", "Inline event handler", "javascript: URI"]
        xss_count = sum(stats["attack_patterns"].get(p, 0) for p in xss_patterns)
        if xss_count > 0:
            recs.append(
                f"XSS attempts detected ({xss_count} events). "
                "Ensure all output is HTML-escaped before rendering."
            )

        if threat_level == "CRITICAL":
            recs.append(
                "CRITICAL threat level reached. "
                "Consider temporary geo-blocking or rate limiting at the server level."
            )

        if not recs:
            recs.append("No immediate action required. System appears stable.")

        return recs
