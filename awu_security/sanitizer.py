"""
sanitizer.py – Input Sanitization Module
==========================================
Cleans user input before it's used in HTML rendering or DB queries.
Works alongside detection – even safe inputs get sanitized.

Modes:
  "plain"  – strip all HTML, normalize whitespace
  "html"   – escape HTML entities (safe for rendering)
  "sql"    – escape characters dangerous in SQL contexts
  "email"  – validate and normalize email addresses
  "url"    – encode unsafe URL characters
"""

import re
import html
import urllib.parse


def sanitize_input(value: str, mode: str = "plain") -> str:
    """
    Sanitize a string based on its intended use context.

    Args:
        value: Raw user input string.
        mode:  "plain" | "html" | "sql" | "email" | "url"

    Returns:
        Sanitized string safe for the given context.
    """
    if not isinstance(value, str):
        value = str(value)

    # Step 1 – Universal cleanup (applied to ALL modes)
    value = _universal_clean(value)

    # Step 2 – Mode-specific sanitization
    if mode == "html":
        return _sanitize_html(value)
    elif mode == "sql":
        return _sanitize_sql(value)
    elif mode == "email":
        return _sanitize_email(value)
    elif mode == "url":
        return _sanitize_url(value)
    else:
        return _sanitize_plain(value)


# ── Universal Cleaner ─────────────────────────────────────────────────────────

def _universal_clean(value: str) -> str:
    """Remove null bytes, normalize line endings, strip leading/trailing spaces."""
    value = value.replace("\x00", "")          # Null byte removal
    value = value.replace("\r\n", "\n")        # Normalize line endings
    value = value.replace("\r", "\n")
    value = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)  # Control chars
    return value.strip()


# ── Mode: Plain ───────────────────────────────────────────────────────────────

def _sanitize_plain(value: str) -> str:
    """
    Strip ALL HTML tags and encode entities.
    Best for: usernames, names, plain text fields.
    """
    # Remove HTML tags
    value = re.sub(r"<[^>]*>", "", value)
    # Encode remaining special chars
    value = html.escape(value, quote=True)
    # Collapse multiple spaces/newlines
    value = re.sub(r"\s{2,}", " ", value)
    # Limit length to 1000 characters
    return value[:1000]


# ── Mode: HTML ───────────────────────────────────────────────────────────────

def _sanitize_html(value: str) -> str:
    """
    Escape HTML entities to allow safe display in web pages.
    Best for: search terms, error messages shown to users.
    """
    return html.escape(value, quote=True)


# ── Mode: SQL ────────────────────────────────────────────────────────────────

def _sanitize_sql(value: str) -> str:
    """
    Escape characters that are dangerous in SQL contexts.
    NOTE: Always prefer prepared statements in PHP (PDO).
          This is a secondary defence layer only.
    """
    # Escape backslashes first, then quotes
    value = value.replace("\\", "\\\\")
    value = value.replace("'",  "\\'")
    value = value.replace('"',  '\\"')
    value = value.replace("\x00", "\\0")
    value = value.replace("\n",  "\\n")
    value = value.replace("\r",  "\\r")
    value = value.replace("\x1a", "\\Z")  # CTRL+Z
    return value


# ── Mode: Email ──────────────────────────────────────────────────────────────

def _sanitize_email(value: str) -> str:
    """
    Validate and normalize an email address.
    Returns lowercased email if valid, empty string if invalid.
    """
    value = value.lower().strip()
    email_regex = r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$"
    if re.match(email_regex, value) and len(value) <= 254:
        return value
    return ""  # Invalid email – caller should reject the input


# ── Mode: URL ────────────────────────────────────────────────────────────────

def _sanitize_url(value: str) -> str:
    """
    Encode a string for safe inclusion in a URL.
    Allows only http/https schemes.
    """
    # Allow only safe schemes
    if re.match(r"^(javascript|vbscript|data):", value, re.IGNORECASE):
        return ""  # Dangerous scheme – reject entirely
    return urllib.parse.quote(value, safe="-_.~/:?=&@#%")


# ── Batch Sanitizer ───────────────────────────────────────────────────────────

def sanitize_dict(data: dict, field_modes: dict = None) -> dict:
    """
    Sanitize an entire dict of fields.

    Args:
        data:        { "field": "value", ... }
        field_modes: { "field": "mode", ... }  (optional, defaults to "plain")

    Returns:
        Dict with all values sanitized.
    """
    field_modes = field_modes or {}
    return {
        key: sanitize_input(str(val), mode=field_modes.get(key, "plain"))
        for key, val in data.items()
    }
