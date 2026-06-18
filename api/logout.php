<?php
require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/db.php';

if (isset($_SESSION['user_id'])) {
    $pdo->prepare("UPDATE user SET session_token = NULL WHERE id = ?")
        ->execute([$_SESSION['user_id']]);
}

session_unset();
session_destroy();
header("Location: ../index.php");
exit;