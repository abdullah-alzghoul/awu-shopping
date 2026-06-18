<?php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function csrf_generate(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_verify(): bool {
    $token = $_POST['csrf_token'] 
           ?? $_SERVER['HTTP_X_CSRF_TOKEN'] 
           ?? '';

    if (empty($_SESSION['csrf_token'])) return false;
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

function csrf_field(): string {
    return '<input type="hidden" name="csrf_token" value="' 
           . htmlspecialchars(csrf_generate()) 
           . '">';
}

function csrf_protect(): void {
    if (!csrf_verify()) {
        http_response_code(403);
        die('
        <!DOCTYPE html>
        <html>
        <head><title>403 - Invalid Request</title></head>
        <body style="font-family:sans-serif;text-align:center;padding:60px;background:#f0f2f5;">
            <div style="background:white;border-radius:12px;padding:40px;max-width:400px;margin:auto;box-shadow:0 2px 20px rgba(0,0,0,0.1);">
                <h1 style="color:#e74c3c;">⚠ Invalid Request</h1>
                <p style="color:#666;">Security token mismatch. Please try again.</p>
                <a href="javascript:history.back()" 
                   style="display:inline-block;margin-top:16px;padding:10px 24px;background:#2b3445;color:white;border-radius:8px;text-decoration:none;">
                   Go Back
                </a>
            </div>
        </body>
        </html>');
    }
}