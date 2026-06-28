<?php
require_once __DIR__ . '/api/session_config.php';
if (isset($_SESSION['user_id'])) {
    header("Location: index2.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Home Page</title>
    <link rel="stylesheet" href="./css/global.css" />
    <link rel="stylesheet" href="./css/header.css" />
    <link rel="shortcut icon" href="./images/bag-shopping-solid.svg" type="image/x-icon" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer"
    />
    <link rel="stylesheet" href="./css/pages/index.css" />
    <link rel="stylesheet" href="./css/footer.css" />
</head>

<body>

    <div class="top-img">

        <header id="headerElement" class="flex">


            <div class="logo">

                <i class="fa-solid fa-bag-shopping"></i>
                <span style="font-weight: bold">AWU</span>
                <p style="letter-spacing: 0.5px">Shopping</p>
            </div>

            <div class="links">

                <a class="register" href="./pages/register.php">
                    <i class="fa-solid fa-user-plus"></i> Register
                </a>
            </div>
        </header>

        <section class="content">
            <p class="lifestyle">Lifestyle collection</p>
            <p class="men">MEN</p>
            <p class="sale">SALE UP TO <span>30% OFF</span></p>
            <p class="free-shipping">Get Free Shipping on orders over $99.00</p>
            <a href="./pages/register.php?panel=signin" class="shop-btn">
    Shop Now
</a>
        </section>
    </div>

    <main class="">
        <h1 class="recommended">
            <i class="fa-solid fa-check"></i> Recommended for you
        </h1>

        <?php
$guestProducts = [
    ['img' => '1.png',  'title' => 'Nike Running Shoes',   'price' => '$89.99'],
    ['img' => '2.webp', 'title' => 'Adidas Sport T-Shirt', 'price' => '$34.99'],
    ['img' => '3.webp', 'title' => 'Gym Gloves Pro',       'price' => '$19.99'],
    ['img' => '4.webp', 'title' => 'Resistance Bands Set', 'price' => '$24.99'],
    ['img' => '5.webp', 'title' => 'Sport Water Bottle',   'price' => '$14.99'],
    ['img' => '6.webp', 'title' => 'Running Shorts',       'price' => '$29.99'],
    ['img' => '7.webp', 'title' => 'Foam Roller',          'price' => '$27.99'],
    ['img' => '8.png',  'title' => 'Sport Backpack',       'price' => '$49.99'],
];
?>
<section class="products flex">
    <?php foreach ($guestProducts as $p): ?>
    <article class="card">
        <a href="./pages/register.php?panel=signin" style="cursor:pointer;">
            <img width="266" src="./images/<?= $p['img'] ?>" alt="<?= $p['title'] ?>">
        </a>
        <div style="width:266px" class="content">
            <h1 class="title"><?= $p['title'] ?></h1>
            <p class="description">Sign in to view full details and add to cart.</p>
            <div class="flex" style="justify-content:space-between;padding-bottom:0.7rem">
                <div class="price"><?= $p['price'] ?></div>
                <button class="add-to-cart flex add-cart requires-login">
                    <i class="fa-solid fa-cart-plus"></i> Add To Cart
                </button>
            </div>
        </div>
    </article>
    <?php endforeach; ?>
</section>
    </main>
    <footer>
        <div class="container">
            <div style="color: white;" class="footer-content">
                <h3>Contact Us</h3>
                <p>Email: info@awu-shopping.com</p>
                <p>Phone: +962 7 0000 0000</p>
                <p>Address: Amman, Jordan</p>
            </div>
            <div style="color: white;" class="footer-content">
                <h3>Quick Links</h3>
                <ul class="list">
                    <li><a href="./index.php">Home</a></li>
                    <li><a href="#">About</a></li>
                    <li><a href="#">Services</a></li>
                    <li><a href="#">Products</a></li>
                    <li><a href="#">Contact</a></li>
                </ul>
            </div>
            <div class="footer-content">
                <h3>Follow Us</h3>
                <ul class="social-icons">
                    <li><a href=""><i class="fab fa-facebook"></i></a></li>
                    <li><a href=""><i class="fab fa-twitter"></i></a></li>
                    <li><a href=""><i class="fab fa-instagram"></i></a></li>
                    <li><a href=""><i class="fab fa-linkedin"></i></a></li>
                </ul>
            </div>
        </div>
        <div class="bottom-bar">
            <p>&copy; 2026 AWU Shopping . All rights reserved</p>
        </div>
    </footer>
<script src="./js/main.js"></script>
</body>
</html>