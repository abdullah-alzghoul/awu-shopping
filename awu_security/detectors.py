"""
detectors.py – Attack Pattern Detection Engine
================================================
Detects: SQL Injection, XSS, Command Injection,
         Path Traversal, Open Redirect.

Each function returns: { "detected": bool, "pattern": str }
"""

import re


_SQLI_PATTERNS = [
    # Classic union-based
    (r"(\bunion\b.{0,30}\bselect\b)",                   "UNION SELECT"),
    # Boolean-based blind
    (r"\b(or|and)\b\s+[\w'\"]+\s*(=|like)\s*[\w'\"]+", "Boolean blind"),
    # Always-true injections  1=1  '1'='1'
    (r"('\s*=\s*'|1\s*=\s*1|true\s*=\s*true)",         "Always-true"),
    # Stacked queries
    (r";\s*(drop|insert|update|delete|alter|create)\b",  "Stacked query"),
    # Common SQLi keywords in suspicious context
    (r"\b(sleep|benchmark|waitfor\s+delay)\s*\(",        "Time-based blind"),
    # Encoded quotes
    (r"(%27|%22|%60)",                                   "URL-encoded quote"),
    # INFORMATION_SCHEMA access
    (r"\binformation_schema\b",                          "Schema enumeration"),
    # hex / char encoding tricks
    (r"\b(0x[0-9a-f]+|char\s*\()",                      "Hex/char encoding"),
    # SELECT INTO OUTFILE (data exfil)
    (r"\bselect\b.+\binto\b.+\boutfile\b",               "File write attempt"),
    # xp_cmdshell (MSSQL RCE)
    (r"\bxp_cmdshell\b",                                 "xp_cmdshell RCE"),
]

def detect_sql_injection(value: str) -> dict:
    """Scan a string for SQL injection patterns."""
    v = value.lower().strip()
    for pattern, label in _SQLI_PATTERNS:
        if re.search(pattern, v, re.IGNORECASE):
            return {"detected": True, "pattern": label}
    return {"detected": False, "pattern": None}



_XSS_PATTERNS = [
    (r"<\s*script[\s>]",                                 "Script tag"),
    (r"<\s*/\s*script\s*>",                              "Closing script tag"),
    (r"javascript\s*:",                                  "javascript: URI"),
    (r"vbscript\s*:",                                    "vbscript: URI"),
    (r"on\w+\s*=\s*[\"']?\s*\w",                        "Inline event handler"),
    (r"<\s*iframe[\s>]",                                 "iframe injection"),
    (r"<\s*img[^>]+src\s*=\s*['\"]?\s*javascript",      "img src javascript"),
    (r"<\s*svg[\s>].+?(on\w+|javascript)",               "SVG XSS"),
    (r"expression\s*\(",                                 "CSS expression()"),
    (r"document\s*\.\s*(cookie|write|location)",         "DOM manipulation"),
    (r"window\s*\.\s*(location|open|eval)",              "Window object access"),
    (r"\beval\s*\(",                                     "eval() call"),
    (r"base64\s*,",                                      "Base64 payload"),
    # URL-encoded variants
    (r"%3c\s*script",                                    "URL-encoded script"),
    (r"&lt;\s*script",                                   "HTML-entity script"),
]

def detect_xss(value: str) -> dict:
    """Scan a string for XSS patterns."""
    v = value.lower().strip()
    for pattern, label in _XSS_PATTERNS:
        if re.search(pattern, v, re.IGNORECASE):
            return {"detected": True, "pattern": label}
    return {"detected": False, "pattern": None}



_CMD_PATTERNS = [
    (r"[;|&`]\s*(ls|dir|cat|rm|del|wget|curl|bash|sh|cmd|powershell)\b",
     "Shell command chaining"),
    (r"\$\s*\(",                                         "Command substitution $()"),
    (r"`[^`]+`",                                         "Backtick execution"),
    (r"\b(wget|curl)\s+https?://",                       "Remote file download"),
    (r"\b(nc|netcat)\s+-",                               "Netcat usage"),
    (r"\/etc\/(passwd|shadow|hosts)\b",                  "Sensitive file access"),
    (r"\b(chmod|chown)\s+[0-9]+",                        "Permission change"),
    (r">\s*\/dev\/null",                                 "Output redirection"),
    (r"\b(python|perl|ruby|php)\s+-[ce]\b",              "Script interpreter exec"),
    (r"2>&1",                                            "Stderr redirect"),
]

def detect_command_injection(value: str) -> dict:
    """Scan a string for OS command injection patterns."""
    v = value.strip()
    for pattern, label in _CMD_PATTERNS:
        if re.search(pattern, v, re.IGNORECASE):
            return {"detected": True, "pattern": label}
    return {"detected": False, "pattern": None}



_PATH_PATTERNS = [
    (r"\.\./",                                           "Directory traversal ../"),
    (r"\.\.\\",                                          "Directory traversal ..\\"),
    (r"%2e%2e[%2f%5c]",                                  "URL-encoded traversal"),
    (r"\.\.[/\\]",                                       "Traversal variant"),
    (r"\/etc\/passwd",                                   "Linux passwd file"),
    (r"\/proc\/self",                                    "Proc filesystem access"),
    (r"c:\\windows\\system32",                           "Windows system32 path"),
    (r"win\.ini|boot\.ini|system\.ini",                  "Windows config file"),
    (r"(\.\./){2,}",                                     "Multiple traversal"),
]

def detect_path_traversal(value: str) -> dict:
    """Scan a string for path traversal patterns."""
    v = value.lower().strip()
    for pattern, label in _PATH_PATTERNS:
        if re.search(pattern, v, re.IGNORECASE):
            return {"detected": True, "pattern": label}
    return {"detected": False, "pattern": None}



_REDIRECT_PATTERNS = [
    (r"https?://(?!localhost|127\.0\.0\.1)",             "External URL in redirect"),
    (r"\/\/[a-z0-9]",                                   "Protocol-relative redirect"),
    (r"javascript:",                                     "javascript: redirect"),
    (r"%0d%0a",                                         "CRLF injection"),
]

def detect_open_redirect(value: str) -> dict:
    """
    Detect open redirect payloads.
    Only meaningful when the value is used as a redirect URL.
    """
    v = value.lower().strip()
    for pattern, label in _REDIRECT_PATTERNS:
        if re.search(pattern, v, re.IGNORECASE):
            return {"detected": True, "pattern": label}
    return {"detected": False, "pattern": None}
