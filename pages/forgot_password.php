<?php
require_once __DIR__ . '/../api/session_config.php';
require_once __DIR__ . '/../api/csrf.php';
require_once __DIR__ . '/../api/security_bridge.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWU Shopping - Forgot Password</title>
    <link rel="stylesheet" href="../css/pages/logo.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <style>
        .forgot-box {
            background: white;
            border-radius: 20px;
            padding: 40px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 5px 30px rgba(0,0,0,0.15);
            text-align: center;
        }
        .forgot-box h1 { font-size: 24px; color: #2b3445; margin-bottom: 8px; }
        .forgot-box p { font-size: 13px; color: #888; margin-bottom: 24px; line-height: 1.5; }
        .forgot-box input {
            width: 100%; padding: 12px 16px;
            border: 1.5px solid #e8e8e8; border-radius: 8px;
            font-size: 14px; margin-bottom: 12px;
            outline: none; transition: 0.2s;
        }
        .forgot-box input:focus { border-color: #2b3445; }
        .forgot-box button {
            width: 100%; padding: 12px;
            background: #2b3445; color: white;
            border: none; border-radius: 8px;
            font-size: 14px; font-weight: 600;
            cursor: pointer; margin-top: 6px; transition: 0.2s;
        }
        .forgot-box button:hover { opacity: 0.9; }
        .forgot-box button:disabled { opacity: 0.6; cursor: not-allowed; }
        .back-link { display: block; margin-top: 20px; font-size: 13px; color: #888; text-decoration: none; }
        .back-link:hover { color: #2b3445; }
        .msg { font-size: 13px; margin: 8px 0; padding: 8px; border-radius: 6px; }
        .msg.success { background: #d5f5e3; color: #1e8449; }
        .msg.error   { background: #fadbd8; color: #a93226; }
        .step { display: none; }
        .step.active { display: block; }
        .code-inputs { display: flex; gap: 8px; justify-content: center; margin: 16px 0; }
        .code-inputs input {
            width: 48px; height: 52px; text-align: center;
            font-size: 20px; font-weight: 600;
            border: 1.5px solid #e8e8e8; border-radius: 8px; margin: 0;
        }
        .code-inputs input:focus { border-color: #2b3445; }
        .pass-wrap { position: relative; }
        .pass-wrap input { padding-right: 40px; }
        .pass-wrap span { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #888; }
    </style>
</head>
<body>

<?php
$msg     = '';
$msgType = '';

if (isset($_POST['send_code'])) {
    if (!csrf_verify()) {
        $msg     = 'Invalid security token. Please refresh and try again.';
        $msgType = 'error';
        goto render;
    }

    $fpCheck = check_otp_send($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    if (!$fpCheck['allowed']) {
        $wait    = max(1, ceil($fpCheck['retry_after_seconds'] / 60));
        $msg     = "Too many attempts. Please wait {$wait} minute(s) before trying again.";
        $msgType = 'error';
        goto render;
    }

    require_once __DIR__ . '/../api/db.php';
    $email = trim($_POST['email'] ?? '');

    $stmt = $pdo->prepare("SELECT id FROM user WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if (!$user) {
        $msg     = 'No account found with this email.';
        $msgType = 'error';
    } else {
        $_SESSION['reset_email'] = $email;

        require_once __DIR__ . '/../api/config.php';
        require __DIR__ . '/../api/phpmailer/src/Exception.php';
        require __DIR__ . '/../api/phpmailer/src/PHPMailer.php';
        require __DIR__ . '/../api/phpmailer/src/SMTP.php';

        $code = random_int(100000, 999999);
        $_SESSION['verify_email']   = $email;
        $_SESSION['verify_code']    = $code;
        $_SESSION['verify_expires'] = time() + 600;

        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host       = SMTP_HOST;
            $mail->SMTPAuth   = true;
            $mail->Username   = SMTP_USER;
            $mail->Password   = SMTP_PASS;
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port       = SMTP_PORT;
            $mail->setFrom(SMTP_FROM, SMTP_FROM_NAME);
            $mail->addAddress($email);
            $mail->isHTML(true);
            $mail->Subject = 'AWU Shopping - Password Reset Code';
            $mail->Body    = '
                <div style="background:#111;color:#fff;padding:20px;text-align:center;font-family:Tahoma,Arial,sans-serif;">
                    <h2>Password Reset Code</h2>
                    <p>Use this code to reset your password:</p>
                    <div style="font-size:40px;letter-spacing:6px;margin:20px 0;">'
                    . htmlspecialchars($code) .
                    '</div>
                    <p style="font-size:12px;color:#ccc;">Valid for 10 minutes. If you did not request this, ignore this email.</p>
                </div>';
            $mail->AltBody = 'Your password reset code is: ' . $code;
            $mail->send();
            header("Location: forgot_password.php?step=2");
            exit;
        } catch (\Exception $e) {
            $msg     = 'Failed to send email. Please try again.';
            $msgType = 'error';
        }
    }
}

if (isset($_POST['verify_code'])) {
    if (!csrf_verify()) {
        $msg     = 'Invalid security token. Please refresh and try again.';
        $msgType = 'error';
        goto render;
    }

    $_SESSION['fp_code_attempts'] = ($_SESSION['fp_code_attempts'] ?? 0) + 1;
    if ($_SESSION['fp_code_attempts'] > 5) {
        unset($_SESSION['verify_code'], $_SESSION['verify_email'],
              $_SESSION['verify_expires'], $_SESSION['fp_code_attempts'],
              $_SESSION['reset_email']);
        $msg     = 'Too many invalid attempts. Please request a new code.';
        $msgType = 'error';
        goto render;
    }

    $code = trim($_POST['code'] ?? '');
    if (
        isset($_SESSION['verify_code'], $_SESSION['verify_email'], $_SESSION['verify_expires']) &&
        $_SESSION['verify_code'] == $code &&
        time() <= $_SESSION['verify_expires']
    ) {
        unset($_SESSION['fp_code_attempts']); 
        $_SESSION['reset_verified'] = true;
        header("Location: forgot_password.php?step=3");
        exit;
    } else {
        $msg     = 'Invalid or expired code. Please try again.';
        $msgType = 'error';
    }
}

if (isset($_POST['reset_password'])) {
    if (!csrf_verify()) {
        $msg     = 'Invalid security token. Please refresh and try again.';
        $msgType = 'error';
        goto render;
    }
    require_once __DIR__ . '/../api/db.php';
    if (!isset($_SESSION['reset_verified']) || !$_SESSION['reset_verified']) {
        header("Location: forgot_password.php");
        exit;
    }

    $password  = $_POST['password']  ?? '';
    $password2 = $_POST['password2'] ?? '';
    $pattern   = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$&@!%^*?])[A-Za-z\d#$&@!%^*?]{10,26}$/';

    if ($password !== $password2) {
        $msg = 'Passwords do not match.'; $msgType = 'error';
    } elseif (!preg_match($pattern, $password)) {
        $msg = 'Password must be 10-26 characters with uppercase, lowercase, number, and symbol.'; $msgType = 'error';
    } else {
        $u = $pdo->prepare("SELECT id, password FROM user WHERE email = ?");
        $u->execute([$_SESSION['reset_email']]);
        $userRow = $u->fetch();

        $hist = $pdo->prepare(
            "SELECT password FROM password_history
             WHERE user_id = ? ORDER BY changed_at DESC LIMIT 5"
        );
        $hist->execute([$userRow['id']]);
        $oldPasswords = $hist->fetchAll();

        array_unshift($oldPasswords, ['password' => $userRow['password']]);

        foreach ($oldPasswords as $old) {
            if (password_verify($password, $old['password'])) {
                $msg     = 'You cannot reuse a recent password. Please choose a new one.';
                $msgType = 'error';
                goto render;
            }
        }

        $hash = password_hash($password, PASSWORD_BCRYPT);

        $pdo->prepare("UPDATE user SET password = ? WHERE email = ?")
            ->execute([$hash, $_SESSION['reset_email']]);

        $pdo->prepare("INSERT INTO password_history (user_id, password) VALUES (?, ?)")
            ->execute([$userRow['id'], $hash]);

        $pdo->prepare(
            "DELETE FROM password_history WHERE user_id = ? AND id NOT IN
             (SELECT id FROM (SELECT id FROM password_history
              WHERE user_id = ? ORDER BY changed_at DESC LIMIT 5) t)"
        )->execute([$userRow['id'], $userRow['id']]);

        unset($_SESSION['reset_email'], $_SESSION['reset_verified'],
              $_SESSION['verify_code'], $_SESSION['verify_email']);

        $_SESSION['success'] = '✅ Password changed successfully. You can now sign in.';
        header("Location: register.php?panel=signin");
        exit;
    }
}

$step = (int)($_GET['step'] ?? 1);
if (!isset($_SESSION['reset_email'])   && $step > 1) $step = 1;
if (!isset($_SESSION['reset_verified']) && $step > 2) $step = 2;

render:
?>

<div class="forgot-box">
    <i class="fa-solid fa-lock" style="font-size:36px;color:#2b3445;margin-bottom:16px;"></i>
    <h1>Forgot Password?</h1>

    <?php if ($msg): ?>
        <div class="msg <?= $msgType ?>"><?= htmlspecialchars($msg) ?></div>
    <?php endif; ?>

    <div class="step <?= $step === 1 ? 'active' : '' ?>">
        <p>Enter your email address and we'll send you a verification code.</p>
        <form method="POST">
            <?= csrf_field() ?>
            <input type="email" name="email" placeholder="Your email address" required>
            <button type="submit" name="send_code">
                <i class="fa-solid fa-paper-plane"></i> Send Code
            </button>
        </form>
    </div>

    <div class="step <?= $step === 2 ? 'active' : '' ?>">
        <p>Enter the 6-digit code sent to<br><strong><?= htmlspecialchars($_SESSION['reset_email'] ?? '') ?></strong></p>
        <form method="POST" onsubmit="collectCode(event)">
            <?= csrf_field() ?>
            <div class="code-inputs">
                <input type="text" maxlength="1" class="code-digit" oninput="moveNext(this)">
                <input type="text" maxlength="1" class="code-digit" oninput="moveNext(this)">
                <input type="text" maxlength="1" class="code-digit" oninput="moveNext(this)">
                <input type="text" maxlength="1" class="code-digit" oninput="moveNext(this)">
                <input type="text" maxlength="1" class="code-digit" oninput="moveNext(this)">
                <input type="text" maxlength="1" class="code-digit" oninput="moveNext(this)">
            </div>
            <input type="hidden" name="code" id="codeInput">
            <button type="submit" name="verify_code">
                <i class="fa-solid fa-check"></i> Verify Code
            </button>
        </form>
        <a href="forgot_password.php" class="back-link">← Try different email</a>
    </div>

    <div class="step <?= $step === 3 ? 'active' : '' ?>">
        <p>Create a new strong password for your account.</p>
        <form method="POST">
            <?= csrf_field() ?>
            <div class="pass-wrap">
                <input type="password" name="password" id="newPass"
                    placeholder="New Password" required
                    minlength="10" maxlength="26"
                    style="padding-right:40px;">
                <span onclick="togglePass('newPass','eye1')">
                    <i id="eye1" class="fa-regular fa-eye-slash"></i>
                </span>
            </div>
            <div class="pass-wrap">
                <input type="password" name="password2" id="newPass2"
                    placeholder="Confirm Password" required
                    style="padding-right:40px;">
                <span onclick="togglePass('newPass2','eye2')">
                    <i id="eye2" class="fa-regular fa-eye-slash"></i>
                </span>
            </div>
            <small style="color:#888;font-size:11px;display:block;margin-bottom:10px;">
                Min 10 chars with uppercase, lowercase, number &amp; symbol
            </small>
            <button type="submit" name="reset_password">
                <i class="fa-solid fa-key"></i> Reset Password
            </button>
        </form>
    </div>

    <a href="register.php" class="back-link">← Back to Sign In</a>
</div>

<script>
function moveNext(input) {
    input.value = input.value.replace(/\D/g, '');
    if (input.value && input.nextElementSibling) {
        input.nextElementSibling.focus();
    }
}

function collectCode(e) {
    const digits = document.querySelectorAll('.code-digit');
    let code = '';
    digits.forEach(d => code += d.value);
    document.getElementById('codeInput').value = code;
    if (code.length < 6) {
        e.preventDefault();
        alert('Please enter all 6 digits.');
    }
}

function togglePass(id, iconId) {
    const input = document.getElementById(id);
    const icon  = document.getElementById(iconId);
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.replace('fa-eye-slash', 'fa-eye');
    } else {
        input.type = 'password';
        icon.classList.replace('fa-eye', 'fa-eye-slash');
    }
}
</script>

</body>
</html>