<?php
/**
 * security_bridge.php
 * ====================
 * PHP helper to call the AWU Security Python API.
 * Include this file in any PHP page that handles user input.
 *
 * Usage:
 *   require_once 'security_bridge.php';
 *
 *   // Scan a single input field before using it
 *   $result = security_scan($_POST['username'], 'username', 'login');
 *   if (!$result['safe']) {
 *       die("Security violation detected.");
 *   }
 *
 *   // Check login attempts (call BEFORE verifying password)
 *   $login = check_login_attempt($ip, $email, $success=false);
 *   if ($login['action'] === 'block') {
 *       die($login['message']);
 *   }
 */

define('SECURITY_API', 'https://127.0.0.1:5000/api');
define('SECURITY_TIMEOUT', 3); // seconds


function security_post(string $endpoint, array $payload): ?array {
    $url  = SECURITY_API . $endpoint;
    $json = json_encode($payload);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $json,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => SECURITY_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER     => false, 
        CURLOPT_SSL_VERIFYHOST     => false,
    ]);

    $response = curl_exec($ch);
    $err      = curl_error($ch);
    curl_close($ch);

    if ($err || !$response) {
        error_log("AWU Security API unreachable: $err");

        $fallbackLog = __DIR__ . '/../logs/security_fallback.log';
        if (!is_dir(dirname($fallbackLog))) {
            mkdir(dirname($fallbackLog), 0755, true);
        }
        file_put_contents($fallbackLog,
            "[" . date('Y-m-d H:i:s') . "] API DOWN — Endpoint: $endpoint | IP: "
            . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n",
            FILE_APPEND | LOCK_EX
        );

        if (strpos($endpoint, '/scan') !== false) {
            $value = $payload['value'] ?? '';
            // Mirrors awu_security/detectors.py's SQLi/XSS/command-injection/
            // path-traversal patterns, so degraded mode stays close to the
            // real detector's coverage instead of the much narrower set this
            // used to check.
            $basicPatterns = [
                // SQL Injection
                '#(\bunion\b.{0,30}\bselect\b)#i',
                '#\b(or|and)\b\s+[\w\'"]+\s*(=|like)\s*[\w\'"]+#i',
                '#(\'\s*=\s*\'|1\s*=\s*1|true\s*=\s*true)#i',
                '#;\s*(drop|insert|update|delete|alter|create)\b#i',
                '#\b(sleep|benchmark|waitfor\s+delay)\s*\(#i',
                '#(%27|%22|%60)#i',
                '#\binformation_schema\b#i',
                '#\b(0x[0-9a-f]+|char\s*\()#i',
                '#\bxp_cmdshell\b#i',
                // XSS
                '#<\s*script[\s>]#i',
                '#<\s*/\s*script\s*>#i',
                '#javascript\s*:#i',
                '#vbscript\s*:#i',
                '#on\w+\s*=\s*["\']?\s*\w#i',
                '#<\s*iframe[\s>]#i',
                '#<\s*svg[\s>].+?(on\w+|javascript)#i',
                '#expression\s*\(#i',
                '#document\s*\.\s*(cookie|write|location)#i',
                '#\beval\s*\(#i',
                '#%3c\s*script#i',
                '#&lt;\s*script#i',
                // Command Injection
                '#[;|&`]\s*(ls|dir|cat|rm|del|wget|curl|bash|sh|cmd|powershell)\b#i',
                '#\$\s*\(#i',
                '#`[^`]+`#',
                '#\b(nc|netcat)\s+-#i',
                '#/etc/(passwd|shadow|hosts)\b#i',
                // Path Traversal
                '#\.\./#i',
                '#\.\.\\\\#i',
                '#%2e%2e[%2f%5c]#i',
                '#c:\\\\windows\\\\system32#i',
            ];
            foreach ($basicPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    return ['safe' => false, 'threats' => ['php_fallback'], 'sanitized_value' => ''];
                }
            }
            return ['safe' => true, 'threats' => [], 'sanitized_value' => $value];
        }

        if (strpos($endpoint, '/login-attempt') !== false) {
            return ['action' => 'block', 'message' => 'Security service is temporarily unavailable. Please try again shortly.'];
        }

        if (strpos($endpoint, '/otp/') !== false) {
            return ['allowed' => false, 'remaining' => 0, 'retry_after_seconds' => 60];
        }

        http_response_code(503);

        http_response_code(503);
        die("<!DOCTYPE html><html><head><title>503 - Service Unavailable</title></head>
        <body style='font-family:sans-serif;text-align:center;padding:60px;background:#f0f2f5;'>
            <div style='background:white;border-radius:12px;padding:40px;max-width:400px;margin:auto;box-shadow:0 2px 20px rgba(0,0,0,0.1);'>
                <h1 style='color:#e74c3c;'>⚠ Service Unavailable</h1>
                <p style='color:#666;'>Security service is temporarily offline. Please try again later.</p>
            </div>
        </body></html>");
    }

    return json_decode($response, true);
}

function security_get(string $endpoint, array $params = []): ?array {
    $url = SECURITY_API . $endpoint;
    if ($params) {
        $url .= '?' . http_build_query($params);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => SECURITY_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
    ]);

    $response = curl_exec($ch);
    curl_close($ch);

    return $response ? json_decode($response, true) : null;
}



/**
 * Scan a single input value for all attack types.
 *
 * @param  string $value   The raw user input to scan.
 * @param  string $field   Field name (for logging).
 * @param  string $context Context (e.g. "login", "register", "search").
 * @param  string $userId  Current user ID or "anonymous".
 * @return array           API response with "safe" (bool) and "threats" (array).
 */
function security_scan(string $value, string $field = 'input',
                        string $context = 'general',
                        string $userId = 'anonymous'): array {
    $result = security_post('/scan', [
        'value'   => $value,
        'field'   => $field,
        'context' => $context,
        'user_id' => $userId,
        'ip'      => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    ]);

    return $result ?? ['safe' => true, 'threats' => [], 'sanitized_value' => $value];
}

/**
 * Scan an entire $_POST or $_GET array.
 * Returns false if ANY field fails, true if all pass.
 *
 * @param  array  $data    Associative array of field => value.
 * @param  string $context Context label.
 * @return bool
 */
function security_scan_all(array $data, string $context = 'general'): bool {
    foreach ($data as $field => $value) {
        $result = security_scan((string)$value, $field, $context);
        if (!$result['safe']) {
            return false;
        }
    }
    return true;
}

/**
 * Record a login attempt and check if the IP should be blocked.
 *
 * @param  string $ip      Client IP (use $_SERVER['REMOTE_ADDR']).
 * @param  string $email   Email being used to log in.
 * @param  bool   $success Whether this attempt succeeded.
 * @return array           API response with "action" and "message".
 */
function check_login_attempt(string $ip, string $email,
                              bool $success = false): array {
    $result = security_post('/login-attempt', [
        'ip'      => $ip,
        'email'   => $email,
        'success' => $success,
    ]);
    return $result ?? ['action' => 'block', 'message' => 'Security service is temporarily unavailable. Please try again shortly.'];
}

function check_otp_send(string $ip): array {
    $result = security_post('/otp/send-check', ['ip' => $ip]);
    return $result ?? ['allowed' => false, 'remaining' => 0, 'retry_after_seconds' => 60];
}

function check_otp_verify(string $ip): array {
    $result = security_post('/otp/verify-check', ['ip' => $ip]);
    return $result ?? ['allowed' => false, 'remaining' => 0, 'retry_after_seconds' => 60];
}

/**
 * Check if the current visitor's IP is banned.
 *
 * @return array  { "banned": bool, "reason": string|null }
 */
function is_ip_banned(): array {
    $ip     = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $result = security_get('/ban/check', ['ip' => $ip]);
    return $result ?? ['banned' => true, 'reason' => 'Security service is temporarily unavailable'];
}

/**
 * Get a sanitized version of a value from the API.
 *
 * @param  string $value  Raw value.
 * @param  string $type   "plain" | "html" | "sql" | "email" | "url"
 * @return string         Sanitized value (original if API unavailable).
 */
function security_sanitize(string $value, string $type = 'plain'): string {
    $result = security_post('/sanitize', ['value' => $value, 'type' => $type]);
    return $result['sanitized'] ?? $value;
}



function block_if_banned(): void {
    $ban = is_ip_banned();
    if ($ban['banned']) {
        http_response_code(403);
        $reason = htmlspecialchars($ban['reason'] ?? 'Security policy', ENT_QUOTES);
        die("
        <!DOCTYPE html>
        <html><head><title>Access Denied</title></head>
        <body style='font-family:sans-serif;text-align:center;padding:60px;'>
            <h1>&#128683; Access Denied</h1>
            <p>Your IP address has been blocked.</p>
            <p><small>Reason: $reason</small></p>
            <p>If you believe this is a mistake, please contact support.</p>
        </body></html>");
    }
}

/*
 * ════════════════════════════════════════════════════════════════════
 * USAGE EXAMPLES
 * ════════════════════════════════════════════════════════════════════
 *
 * --- login.php ---
 *
 *   require_once 'security_bridge.php';
 *   block_if_banned();  // Instantly block banned IPs
 *
 *   if ($_SERVER['REQUEST_METHOD'] === 'POST') {
 *       $ip    = $_SERVER['REMOTE_ADDR'];
 *       $email = $_POST['email'] ?? '';
 *       $pass  = $_POST['password'] ?? '';
 *
 *       // 1. Scan inputs for attacks
 *       $emailCheck = security_scan($email, 'email', 'login');
 *       $passCheck  = security_scan($pass, 'password', 'login');
 *       if (!$emailCheck['safe'] || !$passCheck['safe']) {
 *           die("Invalid input detected.");
 *       }
 *
 *       // 2. Check brute force BEFORE querying the DB
 *       $bf = check_login_attempt($ip, $email, false);
 *       if (in_array($bf['action'], ['block', 'lock', 'ban'])) {
 *           die($bf['message']);
 *       }
 *
 *       // 3. Verify credentials (your existing PHP logic)
 *       $success = verify_credentials($email, $pass);
 *
 *       // 4. Report result back to security API
 *       check_login_attempt($ip, $email, $success);
 *   }
 *
 *
 * --- register.php ---
 *
 *   require_once 'security_bridge.php';
 *   block_if_banned();
 *
 *   if ($_SERVER['REQUEST_METHOD'] === 'POST') {
 *       // Scan all POST fields at once
 *       if (!security_scan_all($_POST, 'register')) {
 *           die("Malicious input detected. Registration blocked.");
 *       }
 *       // ...proceed with registration logic
 *   }
 */
function sync_bans_to_db(PDO $pdo): void {
    $bans = security_get('/ban/list');
    if (!$bans || !isset($bans['bans'])) return;

    foreach ($bans['bans'] as $ban) {
        $check = $pdo->prepare("SELECT id FROM bans WHERE ip = ? AND is_active = 1");
        $check->execute([$ban['ip']]);
        if ($check->fetch()) continue;

        $stmt = $pdo->prepare("
            INSERT INTO bans (ip, reason, until, is_active)
            VALUES (?, ?, ?, 1)
        ");
        $stmt->execute([
            $ban['ip'],
            $ban['reason'] ?? 'Security violation',
            $ban['until']  ?? 'temporary',
        ]);
    }
}

function unban_ip_db(PDO $pdo, string $ip): bool {
    security_post('/unban', ['ip' => $ip]);
    
    security_post('/reset-brute-force', ['ip' => $ip]);

    $stmt = $pdo->prepare("UPDATE bans SET is_active = 0 WHERE ip = ?");
    $stmt->execute([$ip]);
    return true;
}