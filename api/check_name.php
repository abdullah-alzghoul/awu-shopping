<?php
require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/csrf.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !csrf_verify()) {
    http_response_code(403);
    echo json_encode(['available' => false, 'error' => 'Invalid request.']);
    exit;
}

require_once __DIR__ . '/db.php';

$name = trim($_POST['name'] ?? '');

if ($name === '') {
    echo json_encode(['available' => true]);
    exit;
}

$stmt = $pdo->prepare("SELECT id FROM user WHERE name = ?");
$stmt->execute([$name]);

if ($stmt->fetch()) {
    echo json_encode(['available' => false]);
} else {
    echo json_encode(['available' => true]);
}