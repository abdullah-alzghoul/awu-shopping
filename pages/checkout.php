<?php
require_once __DIR__ . '/../api/auth.php';
require_login();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWU Shopping - Checkout</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }

        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 30px 20px;
        }

        .checkout-wrapper {
            width: 100%;
            max-width: 900px;
        }

        .checkout-header {
            text-align: center;
            margin-bottom: 30px;
            color: white;
        }

        .checkout-header .logo {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 6px;
        }

        .checkout-header .logo i {
            color: #e41d43;
            margin-right: 8px;
        }

        .checkout-header p {
            font-size: 14px;
            opacity: 0.7;
        }

        .checkout-card {
            background: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 25px 60px rgba(0,0,0,0.4);
        }

        .checkout-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
        }

        @media (max-width: 650px) {
            .checkout-grid { grid-template-columns: 1fr; }
        }

        .section {
            padding: 35px;
        }

        .section:first-child {
            border-right: 1px solid #f0f0f0;
        }

        .section-title {
            font-size: 16px;
            font-weight: 600;
            color: #2b3445;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
            padding-bottom: 12px;
            border-bottom: 2px solid #f0f0f0;
        }

        .section-title i {
            color: #1976d2;
            font-size: 18px;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }

        .form-group input,
        .form-group select {
            width: 100%;
            padding: 11px 14px;
            border: 1.5px solid #e8e8e8;
            border-radius: 8px;
            font-size: 14px;
            color: #2b3445;
            transition: 0.2s;
            background: #fafafa;
        }

        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #1976d2;
            background: white;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }

        /* Card Visual */
        .card-visual {
            background: linear-gradient(135deg, #1976d2, #0d47a1);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            color: white;
            position: relative;
            overflow: hidden;
        }

        .card-visual::before {
            content: '';
            position: absolute;
            top: -30px; right: -30px;
            width: 120px; height: 120px;
            background: rgba(255,255,255,0.1);
            border-radius: 50%;
        }

        .card-visual::after {
            content: '';
            position: absolute;
            bottom: -40px; right: 40px;
            width: 160px; height: 160px;
            background: rgba(255,255,255,0.06);
            border-radius: 50%;
        }

        .card-chip {
            width: 36px;
            height: 28px;
            background: linear-gradient(135deg, #f9d423, #f0a500);
            border-radius: 4px;
            margin-bottom: 20px;
        }

        .card-number-display {
            font-size: 15px;
            letter-spacing: 3px;
            margin-bottom: 16px;
            font-family: monospace;
        }

        .card-bottom {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            opacity: 0.85;
        }

        /* Accepted Cards */
        .accepted-cards {
            display: flex;
            gap: 8px;
            margin-bottom: 18px;
            flex-wrap: wrap;
        }

        .card-badge {
            background: #f8f9fa;
            border: 1px solid #e8e8e8;
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 12px;
            font-weight: 600;
            color: #2b3445;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .card-badge.visa { color: #1a1f71; }
        .card-badge.master { color: #eb001b; }
        .card-badge.jordan { color: #007a3d; }

        /* Submit Button */
        .submit-section {
            padding: 0 35px 35px;
        }

        .btn-submit {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #1976d2, #0d47a1);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            transition: 0.2s;
        }

        .btn-submit:hover {
            opacity: 0.92;
            transform: translateY(-1px);
        }

        .btn-submit:active {
            transform: translateY(0);
        }

        .secure-note {
            text-align: center;
            margin-top: 14px;
            font-size: 12px;
            color: #aaa;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }

        .back-link {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: rgba(255,255,255,0.6);
            font-size: 13px;
            text-decoration: none;
            transition: 0.2s;
        }

        .back-link:hover { color: white; }
    </style>
</head>
<body>

<div class="checkout-wrapper">

    <!-- Header -->
    <div class="checkout-header">
        <div class="logo">
            <i class="fa-solid fa-bag-shopping"></i>AWU Shopping
        </div>
        <p>Secure Checkout — Jordan</p>
    </div>

    <div class="checkout-card">
        <form action="" method="post" onsubmit="handleSubmit(event)">
            <div class="checkout-grid">

                <!-- Billing Address -->
                <div class="section">
                    <div class="section-title">
                        <i class="fa-solid fa-location-dot"></i>
                        Billing Address
                    </div>

                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" placeholder="e.g. Ahmad Al-Rashid" required>
                    </div>

                    <div class="form-group">
                        <label>Email Address</label>
                        <input type="email" placeholder="example@gmail.com" required>
                    </div>

                    <div class="form-group">
                        <label>Phone Number</label>
                        <input type="tel" placeholder="+962 7X XXX XXXX" required>
                    </div>

                    <div class="form-group">
                        <label>Street Address</label>
                        <input type="text" placeholder="Street, Building No." required>
                    </div>

                    <div class="form-group">
                        <label>City</label>
                        <select required>
                            <option value="">Select City</option>
                            <option>Amman</option>
                            <option selected>Zarqa</option>
                            <option>Irbid</option>
                            <option>Aqaba</option>
                            <option>Madaba</option>
                            <option>Salt</option>
                            <option>Karak</option>
                            <option>Mafraq</option>
                            <option>Jerash</option>
                            <option>Ajloun</option>
                        </select>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label>Governorate</label>
                            <input type="text" value="Jordan" readonly
                                style="background:#f0f0f0;color:#888;">
                        </div>
                        <div class="form-group">
                            <label>Postal Code</label>
                            <input type="text" placeholder="e.g. 13110">
                        </div>
                    </div>
                </div>

                <!-- Payment -->
                <div class="section">
                    <div class="section-title">
                        <i class="fa-solid fa-credit-card"></i>
                        Payment Details
                    </div>

                    <!-- Card Visual -->
                    <div class="card-visual">
                        <div class="card-chip"></div>
                        <div class="card-number-display" id="cardDisplay">
                            •••• •••• •••• ••••
                        </div>
                        <div class="card-bottom">
                            <div>
                                <div style="font-size:10px;opacity:0.7;margin-bottom:2px;">CARD HOLDER</div>
                                <div id="cardName">YOUR NAME</div>
                            </div>
                            <div>
                                <div style="font-size:10px;opacity:0.7;margin-bottom:2px;">EXPIRES</div>
                                <div id="cardExpiry">MM/YY</div>
                            </div>
                        </div>
                    </div>

                    <!-- Accepted Cards -->
                    <div class="accepted-cards">
                        <div class="card-badge visa">
                            <i class="fa-brands fa-cc-visa"></i> Visa
                        </div>
                        <div class="card-badge master">
                            <i class="fa-brands fa-cc-mastercard"></i> Mastercard
                        </div>
                        <div class="card-badge jordan">
                            🇯🇴 CliQ
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Name on Card</label>
                        <input type="text" id="nameInput" placeholder="As printed on card" required
                            oninput="document.getElementById('cardName').textContent = this.value.toUpperCase() || 'YOUR NAME'">
                    </div>

                    <div class="form-group">
                        <label>Card Number</label>
                        <input type="text" id="cardInput" placeholder="1234 5678 9012 3456"
                            maxlength="19" required
                            oninput="formatCard(this)">
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label>Expiry Date</label>
                            <input type="text" placeholder="MM/YY" maxlength="5" required
                                oninput="formatExpiry(this)">
                        </div>
                        <div class="form-group">
                            <label>CVV</label>
                            <input type="password" placeholder="•••" maxlength="3" required>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Submit -->
            <div class="submit-section">
                <button type="submit" class="btn-submit">
                    <i class="fa-solid fa-lock"></i>
                    Place Order Securely
                </button>
                <div class="secure-note">
                    <i class="fa-solid fa-shield-halved"></i>
                    256-bit SSL encrypted — Your data is safe
                </div>
            </div>
        </form>
    </div>

    <a href="product.php" class="back-link">
        ← Back to Shop
    </a>
</div>

<script>
function formatCard(input) {
    let val = input.value.replace(/\D/g, '').substring(0, 16);
    let formatted = val.match(/.{1,4}/g)?.join(' ') || '';
    input.value = formatted;
    let display = val.padEnd(16, '•').match(/.{1,4}/g).join(' ');
    document.getElementById('cardDisplay').textContent = display;
}

function formatExpiry(input) {
    let val = input.value.replace(/\D/g, '').substring(0, 4);
    if (val.length >= 2) val = val.substring(0,2) + '/' + val.substring(2);
    input.value = val;
    document.getElementById('cardExpiry').textContent = val || 'MM/YY';
}

function handleSubmit(e) {
    e.preventDefault();
    alert('✅ Order placed successfully! Thank you for shopping at AWU Shopping.');
    window.location.href = '../home.php';
}
</script>

</body>
</html>