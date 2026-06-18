<?php
require_once __DIR__ . '/session_config.php';
define('SESSION_TIMEOUT', 1800);

if (isset($_SESSION['user_id'])) {
    $last = $_SESSION['last_activity'] ?? time();
    if ((time() - $last) > SESSION_TIMEOUT) {
        session_unset();
        session_destroy();
        header("Location: ../pages/register.php?msg=timeout");
        exit;
    }
    $_SESSION['last_activity'] = time();
}

if (isset($_SESSION['user_id'], $_SESSION['session_token'])) {
    require_once __DIR__ . '/db.php';
    $chk = $pdo->prepare("SELECT session_token FROM user WHERE id = ?");
    $chk->execute([$_SESSION['user_id']]);
    $row = $chk->fetch();

    if ($row && $row['session_token'] === null) {
        $pdo->prepare("UPDATE user SET session_token = ? WHERE id = ?")
            ->execute([$_SESSION['session_token'], $_SESSION['user_id']]);
    } elseif (!$row || $row['session_token'] !== $_SESSION['session_token']) {
        session_unset();
        session_destroy();
        header("Location: ../pages/register.php?msg=session_expired");
        exit;
    }
}

if (!headers_sent()) {
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self';");
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
}

function is_logged_in(): bool {
    return isset($_SESSION['user_id']);
}

function is_manager(): bool {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'manager';
}

function require_login() {
    if (!is_logged_in()) {
        header("Location: ../pages/register.php");
        exit;
    }
}

function require_manager() {
    if (!is_manager()) {
        header("Location: ../pages/no_permission.php");
        exit;
    }
}