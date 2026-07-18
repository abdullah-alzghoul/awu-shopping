# AWU Shopping

A PHP e-commerce application built as a cybersecurity-focused project, pairing a
traditional PHP/MySQL storefront with a dedicated Python security service and a
standalone host intrusion prevention monitor. The security layer — not the
storefront itself — is the point of the project: brute-force protection, OTP
rate limiting, pattern-based threat detection, encrypted audit logging, and
filesystem/firewall-level intrusion monitoring are all implemented from
scratch rather than bolted on as an afterthought.

## Architecture

The project is split across two runtimes that talk to each other over local
HTTPS, plus one independent monitoring process:

- **PHP (Apache/XAMPP)** — the actual storefront: registration, login,
  product browsing, checkout, and the manager dashboard. Handles all
  user-facing logic and owns the MySQL database.
- **Python security service** (`awu_security/`) — a Flask API on
  `127.0.0.1:5000`, secured with a self-signed TLS certificate and a shared
  secret header. Every security-relevant PHP action (login attempts, form
  submissions, ban checks) calls into this service via `api/security_bridge.php`
  rather than implementing that logic in PHP directly. If this service is
  unreachable, the bridge fails **closed** — logins and bans default to
  denied, not allowed, so a downed security service can't be used to bypass
  protection.
- **HIPS monitor** (`awu_security/hips/hips_monitor.py`) — a standalone,
  independently-run process that watches the entire project's files for
  suspicious changes (new executables, modified core files, deletions) and
  can escalate to blocking an IP at the OS firewall level. This is separate
  from the Flask API and isn't required for the storefront or the API to
  function — it's an additional layer that runs on top.

PHP and Python are separate processes specifically so the security logic
isn't constrained by what's convenient to write in PHP — brute-force
tracking, threat-pattern detection, and encrypted logging all benefit from
Python's ecosystem in a way that would be awkward to reimplement natively.

## Setup

**Prerequisites:** XAMPP (Apache + MySQL + PHP) and Python 3.

1. **Clone into your XAMPP web root:**
   ```
   C:\xampp\htdocs\awu-shopping
   ```

2. **Import the database schema** — in phpMyAdmin (or the `mysql` CLI),
   create a database and import `sql/user.sql` into it.

3. **Create a `.env` file in the project root** with the following keys:
   ```
   DB_HOST=localhost
   DB_NAME=your_database_name
   DB_USER=your_mysql_user
   DB_PASS=your_mysql_password
   DB_CHARSET=utf8mb4

   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your_smtp_username
   SMTP_PASS=your_smtp_password
   SMTP_FROM=your_from_address
   SMTP_FROM_NAME=AWU Shopping

   INTERNAL_API_SECRET=a_long_random_value
   ```
   `DB_USER` and `DB_PASS` are required — the app will refuse to start
   without them rather than falling back to a default. Generate
   `INTERNAL_API_SECRET` with:
   ```
   py -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
   This same value must be reachable by both PHP and the Python service —
   they both read it from this one `.env` file.

4. **Install the Python dependencies:**
   ```
   pip install -r awu_security/requirements.txt
   ```

5. **Generate the TLS certificate** the security service will use (one-time,
   run again only if rotating the key):
   ```
   cd awu_security
   py generate_cert.py
   ```

6. **Start the security service** (keep this running in its own terminal):
   ```
   py security_api.py
   ```
   You should see `SSL: ENABLED (HTTPS)` in the startup output — if it says
   `SSL: DISABLED`, step 5 didn't complete correctly.

7. **Optional — start the HIPS monitor** in a separate terminal:
   ```
   cd awu_security/hips
   py hips_monitor.py
   ```

8. **Start Apache and MySQL** from the XAMPP Control Panel.

9. Visit the site through your configured local host.

## Security features

- CSRF tokens (cryptographically random, timing-safe comparison)
- Prepared statements throughout — no raw SQL string interpolation
- Bcrypt password hashing
- Hardened session cookies (`httpOnly`, `secure`, `SameSite=Strict`) with
  session regeneration on login
- Persistent, IP-based brute-force protection for login attempts, with
  tiered escalation (warn → temporary lock → ban)
- Persistent, IP-based rate limiting for OTP send and verify actions,
  independent of login brute-force limits
- Pattern-based detection for SQL injection, XSS, command injection, and
  path traversal, applied to form input
- Fail-closed design: if the security service is unreachable, login and ban
  checks default to deny rather than silently passing everything through
- AES-256-GCM encrypted security event logs (authenticated encryption —
  tampering is detected, not just confidentiality)
- Automated, threshold-based firewall blocking via the HIPS monitor, tuned
  to avoid flagging routine development activity
- TLS-secured, certificate-pinned, shared-secret-authenticated communication
  between the PHP and Python components

## Project structure

```
api/                    PHP backend: auth, CSRF, DB connection, the bridge
                         to the Python security service
awu_security/            Python security service
  hips/                  standalone host intrusion prevention monitor
  logs/                  encrypted security event logs, state files
  ssl/                   self-signed TLS cert/key for the security API
pages/                  application pages (register, checkout, manager
                         dashboard, password reset, etc.)
css/, js/, images/       frontend assets
sql/                    database schema
index.php                logged-out landing page
home.php                logged-in landing page
```