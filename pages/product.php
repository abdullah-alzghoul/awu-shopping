<?php
require_once __DIR__ . '/../api/auth.php';
require_once __DIR__ . '/../api/db.php';
require_login();
$userName = htmlspecialchars($_SESSION['name'] ?? 'User');

$stmt = $pdo->query("SELECT * FROM products ORDER BY featured DESC, id ASC");
$products = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../css/product.css">
    <link href="https://cdn.jsdelivr.net/npm/remixicon@4.7.0/fonts/remixicon.css" rel="stylesheet" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />
    <title>AWU Shopping - Products</title>
    <style>
    .user-info {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .welcome-user {
        font-size: 14px;
        color: #333;
        font-weight: 500;
    }
    .logout-btn {
        font-size: 13px;
        color: #e74c3c;
        text-decoration: none;
        border: 1px solid #e74c3c;
        padding: 4px 10px;
        border-radius: 4px;
        transition: 0.2s;
    }
    .logout-btn:hover {
        background: #e74c3c;
        color: white;
    }
</style>
</head>

<body>
    <header>
    <div class="logo">
        <i class="fa-solid fa-bag-shopping"></i>
        <span style="font-weight: bold">AWU</span>
        <p style="letter-spacing: 0.5px">Shopping</p>
    </div>
    <div class="user-info">
        <span class="welcome-user">👋 <?= $userName ?></span>
        <a href="../api/logout.php" class="logout-btn">Logout</a>
    </div>
    <div id="cart-icon">
        <i class="ri-shopping-bag-line"></i>
        <span class="cart-item-count"></span>
    </div>
</header>

    <div class="cart">
        <h2 class="cart-title">Your Cart</h2>
        <div id="cart-overlay" onclick="closeCart()" style="
            position:fixed;
            top:0;left:0;
            width:calc(100% - 360px);
            height:100%;
            background:rgba(0,0,0,0.3);
            z-index:99;
            display:none;
        "></div>
        <div class="cart-content"></div>
        <div class="total">
            <div class="total-title">Total</div>
            <div class="total-price">$0</div>
        </div>
        <button class="btn-buy">Buy Now</button>
        <i class="ri-close-line" id="cart-close"></i>
    </div>

    <section class="shop">
        <h1 class="section-title" style="
            text-align:center;
            font-size:32px;
            margin-bottom:20px;
            padding-top:20px;
            color:#2b3445;
            position:relative;
            z-index:1;
        ">Shop Products</h1>
        <div class="product-content">
             <?php foreach ($products as $product): ?>
             <div class="product-box">
                <div class="img-box">
                    <img src="../images/<?= htmlspecialchars($product['image']) ?>" 
                        alt="<?= htmlspecialchars($product['name']) ?>">
                </div>
                <h2 class="product-title"><?= htmlspecialchars($product['name']) ?></h2>
                <div class="price-and-card">
                    <span class="price">$<?= number_format($product['price'], 2) ?></span>
                    <i class="ri-shopping-bag-line add-cart"></i>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </section>

    <script src="../js/product.js"></script>
    <script>
    const _autoAdd = new URLSearchParams(window.location.search).get("add");
    if (_autoAdd) {
        history.replaceState(null, null, window.location.pathname);
        document.addEventListener("DOMContentLoaded", () => {
            setTimeout(() => {
                document.querySelectorAll(".product-box").forEach(box => {
                    const title = box.querySelector(".product-title").textContent.trim();
                    if (title === _autoAdd) {
                        box.classList.add("highlighted");
                        const badge = document.createElement("p");
                        badge.classList.add("highlight-badge");
                        badge.textContent = "⭐ Selected for you";
                        box.querySelector(".product-title").before(badge);
                        box.scrollIntoView({ behavior: "smooth", block: "center" });
                        addToCart(box);
                        cart.classList.add("active");
                        setTimeout(() => {
                            box.classList.remove("highlighted");
                            badge.remove();
                        }, 5000);
                    }
                });
            }, 100);
        });
    }
</script>
    <style>
.product-box.highlighted {
    border: 3px solid #1976d2;
    border-radius: 10px;
    box-shadow: 0 0 20px rgba(25, 118, 210, 0.5);
    transform: scale(1.03);
    transition: 0.3s;
}

.highlight-badge {
    background: #1976d2;
    color: white;
    font-size: 12px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 20px;
    display: inline-block;
    margin-bottom: 6px;
}
</style>
</body>

</html>