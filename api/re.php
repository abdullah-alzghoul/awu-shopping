<?php
require_once __DIR__ . '/session_config.php';

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security_bridge.php';

$_SERVER['REMOTE_ADDR'] = ($_SERVER['REMOTE_ADDR'] === '::1') ? '127.0.0.1' : $_SERVER['REMOTE_ADDR'];

$ban = is_ip_banned();
if ($ban['banned']) {
    $_SESSION['error'] = "Your IP has been blocked due to too many failed attempts. Try again later.";
    header("Location: ../pages/register.php");
    exit;
}

require_once __DIR__ . '/csrf.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_protect();
}

if (isset($_POST['signup'])) {
    $name     = trim($_POST['name']     ?? '');
    $email    = trim($_POST['email']    ?? '');
    $code     = trim($_POST['code']     ?? '');
    $password = $_POST['password']      ?? '';

    if (!security_scan_all([
        'name'     => $name,
        'email'    => $email,
        'code'     => $code,
    ], 'register')) {
        $_SESSION['error'] = "Security violation detected. Registration blocked.";
        header("Location: ../pages/register.php?panel=signup");
        exit;
    }

    if (
        !isset($_SESSION['verify_code'], $_SESSION['verify_email'], $_SESSION['verify_expires']) ||
        $_SESSION['verify_email'] !== $email ||
        $_SESSION['verify_code'] != $code ||
        time() > $_SESSION['verify_expires']
    ) {
        $_SESSION['code_attempts'] = ($_SESSION['code_attempts'] ?? 0) + 1;

        if ($_SESSION['code_attempts'] >= 5) {
            unset($_SESSION['verify_code'], $_SESSION['verify_email'],
                  $_SESSION['verify_expires'], $_SESSION['code_attempts']);
            $_SESSION['error'] = "Too many invalid attempts. Please request a new code.";
            header("Location: ../pages/register.php?panel=signup");
            exit;
        }

        $left = 5 - $_SESSION['code_attempts'];
        $_SESSION['error'] = "This code is invalid or expired. Please try again. ({$left} attempt(s) left)";
        header("Location: ../pages/register.php?panel=signup");
        exit;
    }

    unset($_SESSION['code_attempts']);

    if ($name === '' || $email === '' || $password === '') {
        $_SESSION['error'] = "Please fill in all fields.";
        header("Location: ../pages/register.php?panel=signup");
        exit;
    }

    $passwordPattern = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$&@!%^*?])[A-Za-z\d#$&@!%^*?]{10,26}$/';
    if (!preg_match($passwordPattern, $password)) {
        $_SESSION['error'] = "The password is weak. It must be 10 to 26 characters and contain uppercase, lowercase, number, and symbol.";
        header("Location: ../pages/register.php?panel=signup");
        exit;
    }

    $check = $pdo->prepare("SELECT id FROM user WHERE email = ?");
    $check->execute([$email]);
    if ($check->fetch()) {
        $_SESSION['error'] = "This email address has already been used.";
        header("Location: ../pages/register.php?panel=signup");
        exit;
    }

    $checkName = $pdo->prepare("SELECT id FROM user WHERE name = ?");
    $checkName->execute([$name]);
    if ($checkName->fetch()) {
        $_SESSION['error'] = "This name is already taken. Please choose another.";
        header("Location: ../pages/register.php?panel=signup");
        exit;
    }

    $password_hash = password_hash($password, PASSWORD_BCRYPT);

    $stmt = $pdo->prepare("
        INSERT INTO user (name, email, password, role)
        VALUES (?, ?, ?, 'user')
    ");

    if ($stmt->execute([$name, $email, $password_hash])) {
        unset($_SESSION['verify_code'], $_SESSION['verify_email'], $_SESSION['verify_expires']);
        $_SESSION['success'] = "Account created successfully. You can now sign in.";
        header("Location: ../pages/register.php?panel=signin&msg=success");
        exit;
    } else {
        $_SESSION['error'] = "An error occurred while creating the account.";
        header("Location: ../pages/register.php?panel=signup");
        exit;
    }
}

if (isset($_POST['signin'])) {
    $email    = trim($_POST['email']    ?? '');
    $password = $_POST['password']      ?? '';
    $ip       = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if ($ip === '::1') $ip = '127.0.0.1';

    if ($email === '' || $password === '') {
        $_SESSION['error'] = "Please enter your email and password.";
        header("Location: ../pages/register.php");
        exit;
    }

    $_SESSION['failed_attempts'] = $_SESSION['failed_attempts'] ?? 0;

    if ($_SESSION['failed_attempts'] >= 3) {
        $userCaptcha    = trim($_POST['captcha_answer'] ?? '');
        $correctCaptcha = $_SESSION['captcha_answer']  ?? '';

        if ($userCaptcha === '' || $userCaptcha !== (string)$correctCaptcha) {
            $_SESSION['error'] = "Incorrect CAPTCHA answer. Please try again.";
            header("Location: ../pages/register.php");
            exit;
        }
    }

    $emailScan = security_scan($email, 'email', 'login');
    if (!$emailScan['safe']) {
        $_SESSION['error'] = "Invalid input detected.";
        header("Location: ../pages/register.php");
        exit;
    }

    $stmt = $pdo->prepare("SELECT * FROM user WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        check_login_attempt($ip, $email, true);

        session_regenerate_id(true);
        unset($_SESSION['failed_attempts'], $_SESSION['captcha_answer']); 

        $sessionToken = bin2hex(random_bytes(16));
        $stmt2 = $pdo->prepare("UPDATE user SET session_token = ? WHERE id = ?");
        $stmt2->execute([$sessionToken, $user['id']]);

        $_SESSION['user_id']       = $user['id'];
        $_SESSION['name']          = $user['name'];
        $_SESSION['email']         = $user['email'];
        $_SESSION['role']          = $user['role'];
        $_SESSION['login_time']    = date('Y-m-d H:i:s');
        $_SESSION['login_ip']      = $ip;
        $_SESSION['session_token'] = $sessionToken;

        if ($user['role'] === 'manager') {
            header("Location: ../pages/manager.php");
        } else {
            header("Location: ../index2.php");
        }
        exit;

    } else {
        $_SESSION['failed_attempts'] = ($_SESSION['failed_attempts'] ?? 0) + 1;

        $bf = check_login_attempt($ip, $email, false);

        if (in_array($bf['action'], ['warn', 'lock', 'ban', 'block'])) {
            $_SESSION['error'] = $bf['message'];
        } else {
            $_SESSION['error'] = "Incorrect email or password.";
        }

        header("Location: ../pages/register.php");
        exit;
    }
}

header("Location: ../pages/register.php");
exit;