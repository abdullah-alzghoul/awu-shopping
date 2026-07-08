<?php
require_once __DIR__ . '/../api/session_config.php';
require_once __DIR__ . '/../api/csrf.php';
$err   = $_SESSION['error']   ?? '';
$succ  = $_SESSION['success'] ?? '';
unset($_SESSION['error'], $_SESSION['success']);
$panel = $_GET['panel'] ?? 'signin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <link rel="stylesheet" href="../css/pages/logo.css">
    <title>AWU Shopping - Register</title>
</head>

<body>



    <div class="container <?= $panel === 'signup' ? 'active' : '' ?>" id="container">

        <div class="form-container sign-up">
            <form action="../api/login_register.php" method="post">
                <?= csrf_field() ?>
                <h1>Create Account</h1>
                <div class="social-icons">
                    <a href="#" class="icon"><i class="fa-brands fa-google-plus-g"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-facebook-f"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-github"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-linkedin-in"></i></a>
                </div>
                <span>or use your email for registration</span>

                <?php if ($err && $panel === 'signup'): ?>
                    <p style="color:red;font-size:13px;"><?= htmlspecialchars($err) ?></p>
                <?php endif; ?>


                <input type="text" name="name" id="name" placeholder="Name" required
                     oninput="checkName(this.value)">
                <small id="name_msg" style="font-size:12px;margin-top:4px;display:block;"></small>
                <input type="email" name="email" id="email" placeholder="Email" required>

                <div class="verify-block">
                    <button type="button" id="sendCodeBtn">Send Code</button>
                    <input type="text" name="code" id="code" placeholder="Verification Code">
                </div>
                <small id="code_msg"></small>

                <div style="position:relative;width:100%;">
                    <input type="password" name="password" id="signupPassword" placeholder="Password" required
                        minlength="10"
                        maxlength="26"
                        pattern="(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$&@!%^*?])[A-Za-z\d#$&@!%^*?]{10,26}"
                        title="Password must be 10-26 characters with uppercase, lowercase, number, and symbol."
                        style="padding-right:40px;">
                    <span onclick="togglePassword('signupPassword', 'eyeSignup')" 
                            style="position:absolute;right:12px;top:50%;transform:translateY(-50%);cursor:pointer;color:#888;font-size:16px;">
                        <i id="eyeSignup" class="fa-regular fa-eye-slash"></i>
                    </span>
                </div>

                <button type="submit" name="signup">Sign Up</button>
            </form>
        </div>

        <div class="form-container sign-in">
            <form action="../api/login_register.php" method="post">
                <?= csrf_field() ?>
                <h1>Sign In</h1>
                <div class="social-icons">
                    <a href="#" class="icon"><i class="fa-brands fa-google-plus-g"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-facebook-f"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-github"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-linkedin-in"></i></a>
                </div>
                <span>or use your email password</span>

                <?php if ($err && $panel === 'signin'): ?>
                    <p style="color:red;font-size:13px;"><?= htmlspecialchars($err) ?></p>
                <?php endif; ?>

                <?php if ($succ && $panel === 'signin'): ?>
                    <p style="color:green;font-size:13px;text-align:center;margin-bottom:10px;">
                        ✅ <?= htmlspecialchars($succ) ?>
                    </p>
                <?php endif; ?>

                <input type="email" name="email" placeholder="Email" required>
                <div style="position:relative;width:100%;">
                    <input type="password" name="password" id="signinPassword" placeholder="Password" required
                        style="padding-right:40px;">
                    <span onclick="togglePassword('signinPassword', 'eyeSignin')"
                            style="position:absolute;right:12px;top:50%;transform:translateY(-50%);cursor:pointer;color:#888;font-size:16px;">
                        <i id="eyeSignin" class="fa-regular fa-eye-slash"></i>
                    </span>
                </div>
                <a href="forgot_password.php">Forgot Your Password?</a>

                <?php if (($_SESSION['failed_attempts'] ?? 0) >= 3): ?>
                <?php
                    $n1 = random_int(1, 9);
                    $n2 = random_int(1, 9);
                    $_SESSION['captcha_answer'] = $n1 + $n2;
                ?>
                <div style="margin:10px 0;padding:12px;background:#fff8e1;border:1.5px solid #f39c12;border-radius:8px;font-size:13px;">
                    <label style="display:block;margin-bottom:6px;color:#555;">
                        Security Check: What is <strong><?= $n1 ?> + <?= $n2 ?></strong>?
                    </label>
                    <input type="number" name="captcha_answer" placeholder="Your answer"
                           required min="1" max="18" autocomplete="off"
                           style="width:100%;padding:8px 12px;border:1.5px solid #e8e8e8;border-radius:6px;font-size:14px;">
                </div>
                <?php endif; ?>

                <button type="submit" name="signin">Sign In</button>
            </form>
        </div>

        <div class="toggle-container">
            <div class="toggle">
                <div class="toggle-panel toggle-left">
                    <h1>Welcome Back!</h1>
                    <p>Enter your personal details to use all site features</p>
                    <button class="hidden" id="login">Sign In</button>
                </div>
                <div class="toggle-panel toggle-right">
                    <h1>Hello, Friend!</h1>
                    <p>Register with your personal details to use all site features</p>
                    <button class="hidden" id="register">Sign Up</button>
                </div>
            </div>
        </div>

    </div>

    <script src="../js/main.js"></script>
    <script>
function togglePassword(inputId, iconId) {
    const input = document.getElementById(inputId);
    const icon  = document.getElementById(iconId);
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    }
}
</script>
<script>
let nameTimer = null;

function checkName(value) {
    const msg = document.getElementById('name_msg');
    
    if (value.trim().length < 2) {
        msg.textContent = '';
        return;
    }

    clearTimeout(nameTimer);
    msg.style.color = '#888';
    msg.textContent = 'Checking...';

    nameTimer = setTimeout(() => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '../api/check_name.php', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    const res = JSON.parse(xhr.responseText);
                    if (res.available) {
                        msg.style.color = 'green';
                        msg.textContent = '✅ Name is available';
                    } else {
                        msg.style.color = 'red';
                        msg.textContent = '❌ This name is already taken. Please choose another.';
                    }
                } catch(e) {
                    msg.textContent = '';
                }
            }
        };

        const csrfToken = document.querySelector('input[name="csrf_token"]').value;
        xhr.send('name=' + encodeURIComponent(value) + '&csrf_token=' + encodeURIComponent(csrfToken));
    }, 500);
}
</script>
</body>

</html>