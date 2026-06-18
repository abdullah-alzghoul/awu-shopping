<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/csrf.php';
require_login();

header('Content-Type: application/json');

$action = $_POST['action'] ?? '';
$userId = $_SESSION['user_id'];

if ($action === 'change_name') {
    if (!csrf_verify()) {
        echo json_encode(['success' => false, 'message' => 'Invalid security token.']);
        exit;
    }
    $newName = trim($_POST['name'] ?? '');

    if ($newName === '') {
        echo json_encode(['success' => false, 'message' => 'Name cannot be empty.']);
        exit;
    }

    $stmt = $pdo->prepare("SELECT name_changed_at FROM user WHERE id = ?");
    $stmt->execute([$userId]);
    $user = $stmt->fetch();

    if ($user['name_changed_at']) {
        $lastChange = new DateTime($user['name_changed_at']);
        $now        = new DateTime();
        $diff       = $now->diff($lastChange)->days;
        if ($diff < 60) {
            $remaining = 60 - $diff;
            echo json_encode([
                'success' => false,
                'message' => "You can change your name again in $remaining days."
            ]);
            exit;
        }
    }

    $check = $pdo->prepare("SELECT id FROM user WHERE name = ? AND id != ?");
    $check->execute([$newName, $userId]);
    if ($check->fetch()) {
        echo json_encode(['success' => false, 'message' => 'This name is already taken.']);
        exit;
    }

    $stmt = $pdo->prepare("UPDATE user SET name = ?, name_changed_at = NOW() WHERE id = ?");
    $stmt->execute([$newName, $userId]);

    $_SESSION['name'] = $newName;
    echo json_encode(['success' => true, 'message' => 'Name updated successfully!', 'name' => $newName]);
    exit;
}

if ($action === 'update_avatar') {
    if (!csrf_verify()) {
        echo json_encode(['success' => false, 'message' => 'Invalid security token.']);
        exit;
    }

    $stmtUser = $pdo->prepare("SELECT avatar_image FROM user WHERE id = ?");
    $stmtUser->execute([$userId]);
    $userData = $stmtUser->fetch();

    $shape  = $_POST['shape']  ?? 'circle';
    $color  = $_POST['color']  ?? '#1f4fff';
    $letter = $_POST['letter'] ?? '';

    $allowedShapes = ['circle', 'square', 'triangle'];
    if (!in_array($shape, $allowedShapes)) $shape = 'circle';
    if (!preg_match('/^#[0-9a-fA-F]{6}$/', $color)) $color = '#1f4fff';

    $avatarImage = $userData['avatar_image'] ?? '';

    if (isset($_FILES['avatar_img']) && $_FILES['avatar_img']['error'] === 0) {
        $allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        $mime    = mime_content_type($_FILES['avatar_img']['tmp_name']);

        if (!in_array($mime, $allowed)) {
            echo json_encode(['success' => false, 'message' => 'Invalid image format.']);
            exit;
        }

        if ($_FILES['avatar_img']['size'] > 2097152) {
            echo json_encode(['success' => false, 'message' => 'Image too large. Maximum size is 2MB.']);
            exit;
        }

        $mimeToExt = [
            'image/jpeg' => 'jpg',
            'image/png'  => 'png',
            'image/webp' => 'webp',
            'image/gif'  => 'gif',
        ];
        $ext = $mimeToExt[$mime] ?? 'jpg';
        $filename = 'avatar_' . $userId . '_' . time() . '.' . $ext;
        $dest     = __DIR__ . '/../images/avatars/' . $filename;

        if (!is_dir(__DIR__ . '/../images/avatars/')) {
            mkdir(__DIR__ . '/../images/avatars/', 0755, true);
        }

        $oldImage = $userData['avatar_image'] ?? '';
        if ($oldImage) {
            $oldPath = __DIR__ . '/../images/avatars/' . $oldImage;
            if (file_exists($oldPath)) {
                unlink($oldPath);
            }
        }
        move_uploaded_file($_FILES['avatar_img']['tmp_name'], $dest);
        $avatarImage = $filename;
    }

    $stmt = $pdo->prepare("
        UPDATE user SET avatar_shape = ?, avatar_color = ?, avatar_letter = ?, avatar_image = ?
        WHERE id = ?
    ");
    $stmt->execute([$shape, $color, $letter, $avatarImage, $userId]);

    $_SESSION['avatar_shape']  = $shape;
    $_SESSION['avatar_color']  = $color;
    $_SESSION['avatar_letter'] = $letter;
    $_SESSION['avatar_image']  = $avatarImage;

    echo json_encode(['success' => true, 'message' => 'Avatar updated!']);
    exit;
}

echo json_encode(['success' => false, 'message' => 'Invalid action.']);