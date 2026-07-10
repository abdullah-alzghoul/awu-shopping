<?php
require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/csrf.php';

header('Content-Type: application/json; charset=utf-8');

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/phpmailer/src/Exception.php';
require __DIR__ . '/phpmailer/src/PHPMailer.php';
require __DIR__ . '/phpmailer/src/SMTP.php';
require __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request.']);
    exit;
}

if (!csrf_verify()) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Invalid security token. Please refresh the page.']);
    exit;
}

require_once __DIR__ . '/security_bridge.php';

$rateCheck = check_otp_send($_SERVER['REMOTE_ADDR'] ?? 'unknown');
if (!$rateCheck['allowed']) {
    $waitMinutes = max(1, ceil($rateCheck['retry_after_seconds'] / 60));
    echo json_encode([
        'success' => false,
        'message' => "Too many requests. Please wait {$waitMinutes} minute(s) before trying again."
    ]);
    exit;
}

$name  = trim($_POST['name']  ?? '');
$email = trim($_POST['email'] ?? '');

if ($email === '') {
    echo json_encode(['success' => false, 'message' => 'Please enter your email address.']);
    exit;
}

$emailScan = security_scan($email, 'email', 'send_code');
if (!$emailScan['safe']) {
    echo json_encode(['success' => false, 'message' => 'Invalid input detected.']);
    exit;
}

$code = random_int(100000, 999999);

$_SESSION['verify_email']   = $email;
$_SESSION['verify_code']    = $code;
$_SESSION['verify_expires'] = time() + 600; 

$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = SMTP_HOST;
    $mail->SMTPAuth   = true;
    $mail->Username   = SMTP_USER;
    $mail->Password   = SMTP_PASS;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = SMTP_PORT;

    $mail->setFrom(SMTP_FROM, SMTP_FROM_NAME);
    $mail->addAddress($email, $name ?: 'User');

    $mail->isHTML(true);
    $mail->Subject = 'AWU Shopping - Verification Code';
    $mail->Body    = '
        <div style="background:#111;color:#fff;padding:20px;text-align:center;font-family:Tahoma,Arial,sans-serif;">
            <h2>Verify your new account</h2>
            <p>To verify your email, use the following verification code:</p>
            <div style="font-size:40px;letter-spacing:6px;margin:20px 0;">
                ' . htmlspecialchars($code) . '
            </div>
            <p style="font-size:12px;color:#ccc;">
                If you did not request this code, you can ignore this message.
            </p>
        </div>
    ';
    $mail->AltBody = 'Your verification code is: ' . $code;

    $mail->send();

    echo json_encode(['success' => true, 'message' => 'The code has been sent to your email.']);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Failed to send email: ' . $mail->ErrorInfo]);
}