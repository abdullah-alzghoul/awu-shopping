<?php
require_once __DIR__ . '/api/auth.php';
require_once __DIR__ . '/api/db.php';
require_once __DIR__ . '/api/csrf.php';
require_login();

$name = $_SESSION['name'] ?? 'User';
$firstLetter = strtoupper(mb_substr($name, 0, 1, 'UTF-8'));

$stmt = $pdo->prepare("SELECT * FROM user WHERE id = ?");
$stmt->execute([$_SESSION['user_id']]);
$userData = $stmt->fetch();

$stmt = $pdo->query("SELECT * FROM products WHERE featured = 1 ORDER BY id ASC");
$featuredProducts = $stmt->fetchAll();

$avatarShape  = $userData['avatar_shape']  ?? 'circle';
$avatarColor  = $userData['avatar_color']  ?? '#1f4fff';
$avatarLetter = $userData['avatar_letter'] ?: $firstLetter;
$avatarImage  = $userData['avatar_image']  ?? '';
$nameChangedAt = $userData['name_changed_at'] ?? null;

$daysLeft = 0;
if ($nameChangedAt) {
    $lastChange = new DateTime($nameChangedAt);
    $now        = new DateTime();
    $diff       = $now->diff($lastChange)->days;
    $daysLeft   = max(0, 60 - $diff);
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
    <div class="user-menu">
        <!-- Avatar -->
        <div class="avatar-display shape-<?= $avatarShape ?>"
            id="userAvatar"
            style="<?= $avatarImage ? '' : "background:$avatarColor;" ?>"
            onclick="openSettings()">
            <?php if ($avatarImage): ?>
                <img src="./images/avatars/<?= htmlspecialchars($avatarImage) ?>"
                     style="width:100%;height:100%;object-fit:cover;border-radius:inherit;">
            <?php else: ?>
                <?= htmlspecialchars($avatarLetter) ?>
            <?php endif; ?>
        </div>

        <span class="user-name"><?= htmlspecialchars($name) ?></span>

        <!-- Settings Icon -->
        <span class="settings-icon" onclick="openSettings()" title="Settings">
            <i class="fa-solid fa-sliders"></i>
        </span>

        <a href="api/logout.php" class="logout-link">Logout</a>
    </div>
</div>
            </div>
        </header>

        <section class="content">
            <p class="lifestyle">Lifestyle collection</p>
            <p class="men">MEN</p>
            <p class="sale">SALE UP TO <span>30% OFF</span></p>
            <p class="free-shipping">Get Free Shipping on orders over $99.00</p>
            <a href="./pages/product.php" class="shop-btn">
    Shop Now
</a>
        </section>
    </div>

    <main class="">
        <h1 class="recommended">
            <i class="fa-solid fa-check"></i> Recommended for you
        </h1>

        <section class="products flex">
            <?php foreach ($featuredProducts as $product): ?>
            <article class="card">
                <a href="./pages/product.php">
                    <img width="266" src="./images/<?= htmlspecialchars($product['image']) ?>" 
                        alt="<?= htmlspecialchars($product['name']) ?>"/>
                </a>

                <div style="width: 266px" class="content">
                    <h1 class="title"><?= htmlspecialchars($product['name']) ?></h1>
                    <p class="description"><?= htmlspecialchars($product['description']) ?></p>

                    <div class="flex" style="justify-content: space-between; padding-bottom: 0.7rem">
                        <div class="price">$<?= number_format($product['price'], 2) ?></div>
                        <button class="add-to-cart flex" 
                            onclick="window.location.href='./pages/product.php?add=<?= urlencode($product['name']) ?>'">
                            <i class="fa-solid fa-cart-plus"></i>
                            Add To Cart
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
<div id="productModal" style="
    display:none;
    position:fixed;
    top:0;left:0;
    width:100%;height:100%;
    background:rgba(0,0,0,0.6);
    z-index:9999;
    justify-content:center;
    align-items:center;
    padding:20px;
">
    <div style="
        background:#fff;
        border-radius:16px;
        width:100%;
        max-width:480px;
        position:relative;
        box-shadow:0 10px 40px rgba(0,0,0,0.3);
        overflow:hidden;
    ">
        <button onclick="closeModal()" style="
            position:absolute;top:12px;right:12px;
            background:#e74c3c;color:white;
            border:none;border-radius:50%;
            width:32px;height:32px;
            font-size:18px;cursor:pointer;
            display:flex;align-items:center;justify-content:center;
            z-index:10;
            line-height:1;
        ">✕</button>

        <img id="modalImg" src="" style="
            width:100%;
            height:260px;
            object-fit:cover;
            display:block;
        ">

        <div style="padding:20px;">
            <h2 id="modalTitle" style="
                font-size:20px;
                margin-bottom:8px;
                color:#2b3445;
            "></h2>
            <p id="modalDesc" style="
                font-size:13px;
                color:#666;
                line-height:1.6;
                margin-bottom:12px;
            "></p>
            <p id="modalPrice" style="
                font-size:22px;
                font-weight:bold;
                color:#e41d43;
                margin-bottom:16px;
            "></p>
            <button id="modalCartBtn" style="
                background:#1976d2;
                color:white;
                padding:12px;
                border-radius:8px;
                font-size:14px;
                cursor:pointer;
                border:none;
                width:100%;
                font-weight:500;
            ">
                🛒 Add To Cart
            </button>
        </div>
    </div>
</div>

<script>
function openModal(img, title, desc, price, productName) {
    document.getElementById('modalImg').src = img;
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalDesc').textContent = desc;
    document.getElementById('modalPrice').textContent = price;
    document.getElementById('productModal').style.display = 'flex';
    document.getElementById('modalCartBtn').onclick = function() {
        closeModal();
        window.location.href = './pages/product.php?add=' + encodeURIComponent(productName);
    };
}

function closeModal() {
    document.getElementById('productModal').style.display = 'none';
}

document.getElementById('productModal').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
});
</script>

<div class="settings-overlay" id="settingsOverlay" onclick="closeSettingsOutside(event)">
    <div class="settings-modal">

        <div class="settings-header">
            <h2><i class="fa-solid fa-gear"></i> Account Settings</h2>
            <button class="settings-close" onclick="closeSettings()">✕</button>
        </div>

        <div class="settings-body">
            <input type="hidden" id="csrfToken" value="<?= csrf_generate() ?>">

            <div class="settings-section">
                <h3><i class="fa-solid fa-user-pen"></i> Display Name</h3>

                <?php if ($daysLeft > 0): ?>
                    <div class="settings-msg error" style="display:block;">
                        ⏳ You can change your name again in <strong><?= $daysLeft ?> days</strong>.
                    </div>
                <?php endif; ?>

                <div id="nameMsg" class="settings-msg"></div>

                <input type="text" class="settings-input" id="newName"
                       value="<?= htmlspecialchars($name) ?>"
                       placeholder="Enter new name"
                       <?= $daysLeft > 0 ? 'disabled' : '' ?>>

                <small style="color:#aaa;font-size:12px;display:block;margin-bottom:10px;">
                    <i class="fa-solid fa-clock"></i> Name can only be changed once every 60 days.
                </small>

                <?php if ($daysLeft === 0): ?>
                    <button class="settings-btn primary" onclick="changeName()">
                        <i class="fa-solid fa-check"></i> Save Name
                    </button>
                <?php endif; ?>
            </div>

            <div class="settings-section">
                <h3><i class="fa-solid fa-palette"></i> Customize Avatar</h3>

                <div id="avatarMsg" class="settings-msg"></div>

                <div class="avatar-preview-wrap">
                    <div class="avatar-preview shape-<?= $avatarShape ?>"
                         id="avatarPreview"
                         style="background:<?= $avatarColor ?>">
                        <?php if ($avatarImage): ?>
                            <img src="./images/avatars/<?= htmlspecialchars($avatarImage) ?>"
                                 style="width:100%;height:100%;object-fit:cover;">
                        <?php else: ?>
                            <span id="previewLetter"><?= htmlspecialchars($avatarLetter) ?></span>
                        <?php endif; ?>
                    </div>
                </div>

                <p style="font-size:12px;color:#888;margin-bottom:8px;font-weight:500;">Shape</p>
                <div class="shape-selector">
                    <div class="shape-option <?= $avatarShape === 'circle' ? 'selected' : '' ?>"
                         onclick="selectShape('circle', this)">
                        <div class="shape-demo circle"></div>
                        <span>Circle</span>
                    </div>
                    <div class="shape-option <?= $avatarShape === 'square' ? 'selected' : '' ?>"
                         onclick="selectShape('square', this)">
                        <div class="shape-demo square"></div>
                        <span>Square</span>
                    </div>
                    <div class="shape-option <?= $avatarShape === 'triangle' ? 'selected' : '' ?>"
                         onclick="selectShape('triangle', this)">
                        <div class="shape-demo triangle"></div>
                        <span>Triangle</span>
                    </div>
                </div>

                <p style="font-size:12px;color:#888;margin-bottom:8px;font-weight:500;">Color</p>
                <div class="color-options">
                    <?php
                    $colors = ['#1f4fff','#e74c3c','#27ae60','#f39c12','#9b59b6','#1abc9c','#e91e63','#ff5722','#2b3445','#00bcd4'];
                    foreach ($colors as $c):
                    ?>
                    <div class="color-dot <?= $avatarColor === $c ? 'selected' : '' ?>"
                         style="background:<?= $c ?>"
                         onclick="selectColor('<?= $c ?>')"
                         title="<?= $c ?>"></div>
                    <?php endforeach; ?>
                    <input type="color" id="customColor" value="<?= $avatarColor ?>"
                           onchange="selectColor(this.value)"
                           style="width:32px;height:32px;border:none;border-radius:50%;cursor:pointer;padding:0;">
                </div>

                <p style="font-size:12px;color:#888;margin-bottom:8px;font-weight:500;">Letter / Initial</p>
                <input type="text" class="settings-input" id="avatarLetter"
                       value="<?= htmlspecialchars($avatarLetter) ?>"
                       maxlength="2" placeholder="e.g. A"
                       oninput="document.getElementById('previewLetter').textContent = this.value || '?'">

                <p style="font-size:12px;color:#888;margin-bottom:8px;font-weight:500;">Or upload image</p>
                <input type="file" id="avatarFile" accept="image/*"
                       onchange="previewAvatarImage(this)"
                       style="font-size:13px;margin-bottom:14px;">

                <input type="hidden" id="selectedShape" value="<?= $avatarShape ?>">
                <input type="hidden" id="selectedColor" value="<?= $avatarColor ?>">

                <button class="settings-btn primary" onclick="saveAvatar()">
                    <i class="fa-solid fa-floppy-disk"></i> Save Avatar
                </button>
            </div>

        </div>
    </div>
</div>

<script>
function openSettings() {
    document.getElementById('settingsOverlay').classList.add('active');
}

function closeSettings() {
    document.getElementById('settingsOverlay').classList.remove('active');
}

function closeSettingsOutside(e) {
    if (e.target === document.getElementById('settingsOverlay')) closeSettings();
}

function changeName() {
    const name = document.getElementById('newName').value.trim();
    const msg  = document.getElementById('nameMsg');

    if (!name) {
        showMsg(msg, 'error', 'Please enter a name.');
        return;
    }

    const fd = new FormData();
    fd.append('action', 'change_name');
    fd.append('csrf_token', document.getElementById('csrfToken').value);
    fd.append('name', name);

    fetch('../api/update_profile.php', { method: 'POST', body: fd })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                showMsg(msg, 'success', res.message);
                document.querySelector('.user-name').textContent = res.name;
                document.getElementById('previewLetter').textContent =
                    res.name.charAt(0).toUpperCase();
            } else {
                showMsg(msg, 'error', res.message);
            }
        });
}

function selectShape(shape, el) {
    document.getElementById('selectedShape').value = shape;
    document.querySelectorAll('.shape-option').forEach(e => e.classList.remove('selected'));
    el.classList.add('selected');

    const preview = document.getElementById('avatarPreview');
    preview.className = 'avatar-preview shape-' + shape;
}

function selectColor(color) {
    document.getElementById('selectedColor').value = color;
    document.getElementById('customColor').value = color;
    document.querySelectorAll('.color-dot').forEach(el => el.classList.remove('selected'));
    document.getElementById('avatarPreview').style.background = color;
}

function previewAvatarImage(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = e => {
            const preview = document.getElementById('avatarPreview');
            preview.innerHTML = `<img src="${e.target.result}"
                style="width:100%;height:100%;object-fit:cover;border-radius:inherit;">`;
        };
        reader.readAsDataURL(input.files[0]);
    }
}

function saveAvatar() {
    const msg    = document.getElementById('avatarMsg');
    const shape  = document.getElementById('selectedShape').value;
    const color  = document.getElementById('selectedColor').value;
    const letter = document.getElementById('avatarLetter').value;
    const file   = document.getElementById('avatarFile').files[0];

    const fd = new FormData();
    fd.append('action', 'update_avatar');
    fd.append('csrf_token', document.getElementById('csrfToken').value);
    fd.append('shape', shape);
    fd.append('color', color);
    fd.append('letter', letter);
    if (file) fd.append('avatar_img', file);

    fetch('../api/update_profile.php', { method: 'POST', body: fd })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                showMsg(msg, 'success', res.message);
                updateHeaderAvatar(shape, color, letter);
                setTimeout(() => location.reload(), 1000);
            } else {
                showMsg(msg, 'error', res.message);
            }
        });
}

function updateHeaderAvatar(shape, color, letter) {
    const avatar = document.getElementById('userAvatar');
    if (avatar) {
        avatar.style.background = color;
        avatar.className = 'avatar-display shape-' + shape;
        avatar.textContent = letter || '?';
    }
}

function showMsg(el, type, text) {
    el.className = 'settings-msg ' + type;
    el.textContent = text;
    el.style.display = 'block';
    setTimeout(() => { el.style.display = 'none'; }, 4000);
}
</script>
</body>

</html>